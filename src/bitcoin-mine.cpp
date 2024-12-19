// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <common/args.h>
#include <common/system.h>
#include <compat/compat.h>
#include <init/common.h>
#include <interfaces/init.h>
#include <interfaces/ipc.h>
#include <logging.h>
#include <sv2/template_provider.h>
#include <tinyformat.h>
#include <util/translation.h>

#ifndef WIN32
// #include <cerrno>
#include <signal.h>
// #include <sys/stat.h>
#endif

static const char* const HELP_USAGE{R"(
bitcoin-mine is a test program for interacting with bitcoin-node via IPC.

Usage:
  bitcoin-mine [options]
)"};

static const char* HELP_EXAMPLES{R"(
Examples:
  # Start separate bitcoin-node that bitcoin-mine can connect to.
  bitcoin-node -regtest -ipcbind=unix

  # Connect to bitcoin-node and print tip block hash.
  bitcoin-mine -regtest

  # Run with debug output.
  bitcoin-mine -regtest -debug=sv2 -loglevel=sv2:trace
)"};

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

static void AddArgs(ArgsManager& args)
{
    SetupHelpOptions(args);
    SetupChainParamsBaseOptions(args);

    const auto defaultBaseParams = CreateBaseChainParams(ChainType::MAIN);
    const auto testnetBaseParams = CreateBaseChainParams(ChainType::TESTNET);
    const auto testnet4BaseParams = CreateBaseChainParams(ChainType::TESTNET4);
    const auto signetBaseParams = CreateBaseChainParams(ChainType::SIGNET);
    const auto regtestBaseParams = CreateBaseChainParams(ChainType::REGTEST);

    args.AddArg("-version", "Print version and exit", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-datadir=<dir>", "Specify data directory", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-ipcconnect=<address>", "Connect to bitcoin-node process in the background to perform online operations. Valid <address> values are 'unix' to connect to the default socket, 'unix:<socket path>' to connect to a socket at a nonstandard path. Default value: unix", ArgsManager::ALLOW_ANY, OptionsCategory::IPC);
    args.AddArg("-sv2bind=<addr>[:<port>]", strprintf("Bind to given address and always listen on it (default: 127.0.0.1). Use [host]:port notation for IPv6."), ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::CONNECTION);
    args.AddArg("-sv2port=<port>", strprintf("Listen for Stratum v2 connections on <port> (default: %u, testnet3: %u, testnet4: %u, signet: %u, regtest: %u).", defaultBaseParams->Sv2Port(), testnetBaseParams->Sv2Port(), testnet4BaseParams->Sv2Port(), signetBaseParams->Sv2Port(), regtestBaseParams->Sv2Port()), ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::CONNECTION);
    args.AddArg("-sv2interval", strprintf("Template Provider block template update interval (default: %d seconds)", Sv2TemplateProviderOptions().fee_check_interval.count()), ArgsManager::ALLOW_ANY, OptionsCategory::BLOCK_CREATION);
    args.AddArg("-sv2feedelta", strprintf("Minimum fee delta for Template Provider to send update upstream (default: %d sat)", uint64_t(Sv2TemplateProviderOptions().fee_delta)), ArgsManager::ALLOW_ANY, OptionsCategory::BLOCK_CREATION);
    init::AddLoggingArgs(args);
}

static bool g_interrupt{false};

#ifndef WIN32
static void registerSignalHandler(int signal, void(*handler)(int))
{
    struct sigaction sa;
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(signal, &sa, nullptr);
}
static void HandleSIGTERM(int)
{
    g_interrupt = true;
}

#endif

MAIN_FUNCTION
{
    ArgsManager& args = gArgs;
    AddArgs(args);
    std::string error_message;
    if (!args.ParseParameters(argc, argv, error_message)) {
        tfm::format(std::cerr, "Error parsing command line arguments: %s\n", error_message);
        return EXIT_FAILURE;
    }
    if (!args.ReadConfigFiles(error_message, true)) {
        tfm::format(std::cerr, "Error reading config files: %s\n", error_message);
        return EXIT_FAILURE;
    }
    if (HelpRequested(args) || args.IsArgSet("-version")) {
        std::string output{strprintf("%s bitcoin-mine version", CLIENT_NAME) + " " + FormatFullVersion() + "\n"};
        if (args.IsArgSet("-version")) {
            output += FormatParagraph(LicenseInfo());
        } else {
            output += HELP_USAGE;
            output += args.GetHelpMessage();
            output += HELP_EXAMPLES;
        }
        tfm::format(std::cout, "%s", output);
        return EXIT_SUCCESS;
    }
    if (!CheckDataDirOption(args)) {
        tfm::format(std::cerr, "Error: Specified data directory \"%s\" does not exist.\n", args.GetArg("-datadir", ""));
        return EXIT_FAILURE;
    }
    SelectParams(args.GetChainType());

    // Set logging options but override -printtoconsole default to depend on -debug rather than -daemon
    init::SetLoggingOptions(args);
    if (auto result{init::SetLoggingCategories(args)}; !result) {
        tfm::format(std::cerr, "Error: %s\n", util::ErrorString(result).original);
        return EXIT_FAILURE;
    }
    if (auto result{init::SetLoggingLevel(args)}; !result) {
        tfm::format(std::cerr, "Error: %s\n", util::ErrorString(result).original);
        return EXIT_FAILURE;
    }
    LogInstance().m_print_to_console = args.GetBoolArg("-printtoconsole", LogInstance().GetCategoryMask());
    if (!init::StartLogging(args)) {
        tfm::format(std::cerr, "Error: StartLogging failed\n");
        return EXIT_FAILURE;
    }

    ECC_Context ecc_context{};

    // Parse -sv2... params
    Sv2TemplateProviderOptions options{};

    const std::string sv2_port_arg = args.GetArg("-sv2port", "");

    if (sv2_port_arg.empty()) {
        options.port = BaseParams().Sv2Port();
    } else {
        if (!ParseUInt16(sv2_port_arg, &options.port) || options.port == 0) {
            tfm::format(std::cerr, "Invalid port %s\n", sv2_port_arg);
            return EXIT_FAILURE;
        }
    }

    if (args.IsArgSet("-sv2bind")) { // Specific bind address
        std::optional<std::string> sv2_bind{args.GetArg("-sv2bind")};
        if (sv2_bind) {
            if (!SplitHostPort(sv2_bind.value(), options.port, options.host)) {
                tfm::format(std::cerr, "Invalid port %d\n", options.port);
                return EXIT_FAILURE;
            }
        }
    }

    options.fee_delta = args.GetIntArg("-sv2feedelta", Sv2TemplateProviderOptions().fee_delta);

    if (args.IsArgSet("-sv2interval")) {
        if (args.GetIntArg("-sv2interval", 0) < 1) {
            tfm::format(std::cerr, "-sv2interval must be at least one second\n");
            return EXIT_FAILURE;
        }
        options.fee_check_interval = std::chrono::seconds(args.GetIntArg("-sv2interval", 0));
    }

    // Connect to existing bitcoin-node process or spawn new one.
    std::unique_ptr<interfaces::Init> mine_init{interfaces::MakeMineInit(argc, argv)};
    assert(mine_init);
    std::unique_ptr<interfaces::Init> node_init;
    try {
        std::string address{args.GetArg("-ipcconnect", "unix")};
        node_init = mine_init->ipc()->connectAddress(address);
    } catch (const std::exception& exception) {
        tfm::format(std::cerr, "Error: %s\n", exception.what());
        tfm::format(std::cerr, "Probably bitcoin-node is not running or not listening on a unix socket. Can be started with:\n\n");
        tfm::format(std::cerr, "    bitcoin-node -chain=%s -ipcbind=unix\n", args.GetChainTypeString());
        return EXIT_FAILURE;
    }
    assert(node_init);
    tfm::format(std::cout, "Connected to bitcoin-node\n");
    std::unique_ptr<interfaces::Mining> mining{node_init->makeMining()};
    assert(mining);

    auto tp = std::make_unique<Sv2TemplateProvider>(*mining);

    if (!tp->Start(options)) {
        tfm::format(std::cerr, "Unable to start Stratum v2 Template Provider");
        return EXIT_FAILURE;
    }

#ifndef WIN32
    registerSignalHandler(SIGTERM, HandleSIGTERM);
    registerSignalHandler(SIGINT, HandleSIGTERM);
#endif

    while(!g_interrupt) {
        UninterruptibleSleep(100ms);
    }

    tp->Interrupt();
    tp->StopThreads();
    tp.reset();

    return EXIT_SUCCESS;
}

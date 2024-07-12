// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <config/bitcoin-config.h> // IWYU pragma: keep

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
#include <tinyformat.h>
#include <util/translation.h>

static const char* const HELP_USAGE{R"(
bitcoin-mine is an test program for interacting with bitcoin-node via IPC.

Usage:
  bitcoin-mine [options] [--] [node options]
)"};

static const char* HELP_EXAMPLES{R"(
Examples:

  # Connect to existing bitcoin-node
  bitcoin-mine -regtest

  # Run with debug output.
  bitcoin-mine -regtest -debug
)"};

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

static void AddArgs(ArgsManager& args)
{
    SetupHelpOptions(args);
    SetupChainParamsBaseOptions(args);
    args.AddArg("-version", "Print version and exit", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-datadir=<dir>", "Specify data directory", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-debug=<category>", "Output debugging information (default: 0).", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    args.AddArg("-ipcconnect=<address>", "Connect to bitcoin-node process in the background to perform online operations. Valid <address> values are 'auto' to try connecting to default socket in <datadir>/sockets/node.sock, 'unix' to connect to the default socket and fail if it isn't available, 'unix:<socket path>' to connect to a socket at a nonstandard path, and -noipcconnect to not try to connect. Default value: auto", ArgsManager::ALLOW_ANY, OptionsCategory::IPC);
}

MAIN_FUNCTION
{
    ArgsManager& args = gArgs;
    AddArgs(args);
    std::string error_message;
    if (!args.ReadConfigFiles(error_message, true)) {
        tfm::format(std::cerr, "Error reading config files: %s\n", error_message);
        return EXIT_FAILURE;
    }
    if (HelpRequested(args) || args.IsArgSet("-version")) {
        std::string output{strprintf("%s bitcoin-mine version", PACKAGE_NAME) + " " + FormatFullVersion() + "\n"};
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

    // check for printtoconsole, allow -debug
    LogInstance().m_print_to_console = args.GetBoolArg("-printtoconsole", args.GetBoolArg("-debug", false));

    if (!CheckDataDirOption(args)) {
        tfm::format(std::cerr, "Error: Specified data directory \"%s\" does not exist.\n", args.GetArg("-datadir", ""));
        return EXIT_FAILURE;
    }
    SelectParams(args.GetChainType());
    if (!init::StartLogging(gArgs)) {
        tfm::format(std::cerr, "Error: StartLogging failed\n");
        return EXIT_FAILURE;
    }

    // Connect to bitcoin-node process
    std::unique_ptr<interfaces::Init> mine_init{interfaces::MakeMineInit(argc, argv)};
    assert(mine_init);
    std::string address{args.GetArg("-ipcconnect", "auto")};
    std::unique_ptr<interfaces::Init> node_init{mine_init->ipc()->connectAddress(address)};

    if (!node_init) {
        tfm::format(std::cout, "Please start Bitcoin Core: bitcoin-node -ipcbind=unix\n");
        return EXIT_FAILURE;
    }

    tfm::format(std::cout, "Connected to bitcoin-node\n");
    std::unique_ptr<interfaces::Mining> mining{node_init->makeMining()};
    assert(mining);

    std::optional<uint256> tip_hash{mining->getTipHash()};
    if (tip_hash) {
        tfm::format(std::cout, "Tip hash is %s.\n", tip_hash->ToString());
    } else {
        tfm::format(std::cout, "Tip hash is null.\n");
    }

    return EXIT_SUCCESS;
}

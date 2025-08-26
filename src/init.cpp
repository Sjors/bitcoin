// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <init.h>

#include <kernel/checks.h>

#include <blockfilter.h>
#include <chain.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <common/args.h>
#include <common/messages.h>
#include <common/system.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <deploymentstatus.h>
#include <hash.h>
#include <init/common.h>
#include <interfaces/chain.h>
#include <interfaces/init.h>
#include <interfaces/ipc.h>
#include <interfaces/mining.h>
#include <interfaces/node.h>
#include <ipc/exception.h>
#include <kernel/caches.h>
#include <kernel/context.h>
#include <key.h>
#include <logging.h>
#include <net.h>
#include <netbase.h>
#include <node/blockmanager_args.h>
#include <node/blockstorage.h>
#include <node/caches.h>
#include <node/chainstate.h>
#include <node/chainstatemanager_args.h>
#include <node/context.h>
#include <node/interface_ui.h>
#include <node/kernel_notifications.h>
#include <node/mempool_args.h>
#include <node/mempool_persist.h>
#include <node/mempool_persist_args.h>
#include <node/miner.h>
#include <policy/feerate.h>
#include <policy/fees.h>
#include <policy/fees_args.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <protocol.h>
#include <scheduler.h>
#include <script/sigcache.h>
#include <sync.h>
#include <txdb.h>
#include <txmempool.h>
#include <util/batchpriority.h>
#include <util/chaintype.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/moneystr.h>
#include <util/result.h>
#include <util/signalinterrupt.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/syserror.h>
#include <util/thread.h>
#include <util/threadnames.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>

#include <algorithm>
#include <cerrno>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <functional>
#include <set>
#include <string>
#include <thread>
#include <vector>

#ifndef WIN32
#include <csignal>
#include <sys/stat.h>
#endif

#include <boost/signals2/signal.hpp>

using common::AmountErrMsg;
using node::ApplyArgsManOptions;
using node::BlockManager;
using node::CalculateCacheSizes;
using node::ChainstateLoadResult;
using node::ChainstateLoadStatus;
using node::DEFAULT_PERSIST_MEMPOOL;
using node::DEFAULT_PRINT_MODIFIED_FEE;
using node::DEFAULT_STOPATHEIGHT;
using node::DumpMempool;
using node::ImportBlocks;
using node::KernelNotifications;
using node::LoadChainstate;
using node::LoadMempool;
using node::MempoolPath;
using node::NodeContext;
using node::ShouldPersistMempool;
using node::VerifyLoadedChainstate;
using util::Join;
using util::ToString;

static constexpr bool DEFAULT_STOPAFTERBLOCKIMPORT{false};

/**
 * String used to describe UNIX epoch time in documentation, factored out to a
 * constant for consistency.
 */
const std::string UNIX_EPOCH_TIME = "UNIX epoch time";

#ifdef WIN32
// Win32 LevelDB doesn't use filedescriptors, and the ones used for
// accessing block files don't count towards the fd_set size limit
// anyway.
#define MIN_LEVELDB_FDS 0
#else
#define MIN_LEVELDB_FDS 150
#endif

/**
 * The PID file facilities.
 */
static const char* BITCOIN_PID_FILENAME = "bitcoind.pid";
/**
 * True if this process has created a PID file.
 * Used to determine whether we should remove the PID file on shutdown.
 */
static bool g_generated_pid{false};

static fs::path GetPidFile(const ArgsManager& args)
{
    return AbsPathForConfigVal(args, args.GetPathArg("-pid", BITCOIN_PID_FILENAME));
}

[[nodiscard]] static bool CreatePidFile(const ArgsManager& args)
{
    if (args.IsArgNegated("-pid")) return true;

    std::ofstream file{GetPidFile(args)};
    if (file) {
#ifdef WIN32
        tfm::format(file, "%d\n", GetCurrentProcessId());
#else
        tfm::format(file, "%d\n", getpid());
#endif
        g_generated_pid = true;
        return true;
    } else {
        return InitError(strprintf(_("Unable to create the PID file '%s': %s"), fs::PathToString(GetPidFile(args)), SysErrorString(errno)));
    }
}

static void RemovePidFile(const ArgsManager& args)
{
    if (!g_generated_pid) return;
    const auto pid_path{GetPidFile(args)};
    if (std::error_code error; !fs::remove(pid_path, error)) {
        std::string msg{error ? error.message() : "File does not exist"};
        LogPrintf("Unable to remove PID file (%s): %s\n", fs::PathToString(pid_path), msg);
    }
}

static std::optional<util::SignalInterrupt> g_shutdown;

void InitContext(NodeContext& node)
{
    assert(!g_shutdown);
    g_shutdown.emplace();

    node.args = &gArgs;
    node.shutdown_signal = &*g_shutdown;
    node.shutdown_request = [&node] {
        assert(node.shutdown_signal);
        if (!(*node.shutdown_signal)()) return false;
        // Wake any threads that may be waiting for the tip to change.
        if (node.notifications) WITH_LOCK(node.notifications->m_tip_block_mutex, node.notifications->m_tip_block_cv.notify_all());
        return true;
    };
}

//////////////////////////////////////////////////////////////////////////////
//
// Shutdown
//

//
// Thread management and startup/shutdown:
//
// The network-processing threads are all part of a thread group
// created by AppInit() or the Qt main() function.
//
// A clean exit happens when the SignalInterrupt object is triggered, which
// makes the main thread's SignalInterrupt::wait() call return, and join all
// other ongoing threads in the thread group to the main thread.
// Shutdown() is then called to clean up database connections, and stop other
// threads that should only be stopped after the main network-processing
// threads have exited.
//
// Shutdown for Qt is very similar, only it uses a QTimer to detect
// ShutdownRequested() getting set, and then does the normal Qt
// shutdown thing.
//

bool ShutdownRequested(node::NodeContext& node)
{
    return bool{*Assert(node.shutdown_signal)};
}

#if HAVE_SYSTEM
static void ShutdownNotify(const ArgsManager& args)
{
    std::vector<std::thread> threads;
    for (const auto& cmd : args.GetArgs("-shutdownnotify")) {
        threads.emplace_back(runCommand, cmd);
    }
    for (auto& t : threads) {
        t.join();
    }
}
#endif

void Interrupt(NodeContext& node)
{
#if HAVE_SYSTEM
    ShutdownNotify(*node.args);
#endif
}

void Shutdown(NodeContext& node)
{
    static Mutex g_shutdown_mutex;
    TRY_LOCK(g_shutdown_mutex, lock_shutdown);
    if (!lock_shutdown) return;
    LogInfo("Shutdown in progress...");
    Assert(node.args);

    /// Note: Shutdown() must be able to handle cases in which initialization failed part of the way,
    /// for example if the data directory was found to be locked.
    /// Be sure that anything that writes files or flushes caches only does this if the respective
    /// module was initialized.
    util::ThreadRename("shutoff");
    if (node.mempool) node.mempool->AddTransactionsUpdated(1);

    for (auto& client : node.chain_clients) {
        try {
            client->stop();
        } catch (const ipc::Exception& e) {
            LogDebug(BCLog::IPC, "Chain client did not disconnect cleanly: %s", e.what());
            client.reset();
        }
    }

    if (node.background_init_thread.joinable()) node.background_init_thread.join();
    // After everything has been shut down, but before things get flushed, stop the
    // the scheduler. After this point, SyncWithValidationInterfaceQueue() should not be called anymore
    // as this would prevent the shutdown from completing.
    if (node.scheduler) node.scheduler->stop();

    if (node.mempool && node.mempool->GetLoadTried() && ShouldPersistMempool(*node.args)) {
        DumpMempool(*node.mempool, MempoolPath(*node.args));
    }

    // FlushStateToDisk generates a ChainStateFlushed callback, which we should avoid missing
    if (node.chainman) {
        LOCK(cs_main);
        for (Chainstate* chainstate : node.chainman->GetAll()) {
            if (chainstate->CanFlushToDisk()) {
                chainstate->ForceFlushStateToDisk();
            }
        }
    }

    // After there are no more peers/RPC left to give us new data which may generate
    // CValidationInterface callbacks, flush them...
    if (node.validation_signals) node.validation_signals->FlushBackgroundCallbacks();

    // Any future callbacks will be dropped. This should absolutely be safe - if
    // missing a callback results in an unrecoverable situation, unclean shutdown
    // would too. The only reason to do the above flushes is to let the wallet catch
    // up with our current chain to avoid any strange pruning edge cases and make
    // next startup faster by avoiding rescan.

    if (node.chainman) {
        LOCK(cs_main);
        for (Chainstate* chainstate : node.chainman->GetAll()) {
            if (chainstate->CanFlushToDisk()) {
                chainstate->ForceFlushStateToDisk();
                chainstate->ResetCoinsViews();
            }
        }
    }

    // If any -ipcbind clients are still connected, disconnect them now so they
    // do not block shutdown.
    if (interfaces::Ipc* ipc = node.init->ipc()) {
        ipc->disconnectIncoming();
    }

    node.chain_clients.clear();
    if (node.validation_signals) {
        node.validation_signals->UnregisterAllValidationInterfaces();
    }
    node.mempool.reset();
    node.fee_estimator.reset();
    node.chainman.reset();
    node.validation_signals.reset();
    node.scheduler.reset();
    node.ecc_context.reset();
    node.kernel.reset();

    RemovePidFile(*node.args);

    LogInfo("Shutdown done");
}

/**
 * Signal handlers are very limited in what they are allowed to do.
 * The execution context the handler is invoked in is not guaranteed,
 * so we restrict handler operations to just touching variables:
 */
#ifndef WIN32
static void HandleSIGTERM(int)
{
    // Return value is intentionally ignored because there is not a better way
    // of handling this failure in a signal handler.
    (void)(*Assert(g_shutdown))();
}

static void HandleSIGHUP(int)
{
    LogInstance().m_reopen_file = true;
}
#else
static BOOL WINAPI consoleCtrlHandler(DWORD dwCtrlType)
{
    if (!(*Assert(g_shutdown))()) {
        LogError("Failed to send shutdown signal on Ctrl-C\n");
        return false;
    }
    Sleep(INFINITE);
    return true;
}
#endif

#ifndef WIN32
static void registerSignalHandler(int signal, void(*handler)(int))
{
    struct sigaction sa;
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(signal, &sa, nullptr);
}
#endif

void SetupServerArgs(ArgsManager& argsman, bool can_listen_ipc)
{
    SetupHelpOptions(argsman);
    argsman.AddArg("-help-debug", "Print help message with debugging options and exit", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST); // server-only for now

    init::AddLoggingArgs(argsman);

    const auto defaultBaseParams = CreateBaseChainParams(ChainType::MAIN);
    const auto testnetBaseParams = CreateBaseChainParams(ChainType::TESTNET);
    const auto testnet4BaseParams = CreateBaseChainParams(ChainType::TESTNET4);
    const auto signetBaseParams = CreateBaseChainParams(ChainType::SIGNET);
    const auto regtestBaseParams = CreateBaseChainParams(ChainType::REGTEST);
    const auto defaultChainParams = CreateChainParams(argsman, ChainType::MAIN);
    const auto testnetChainParams = CreateChainParams(argsman, ChainType::TESTNET);
    const auto testnet4ChainParams = CreateChainParams(argsman, ChainType::TESTNET4);
    const auto signetChainParams = CreateChainParams(argsman, ChainType::SIGNET);
    const auto regtestChainParams = CreateChainParams(argsman, ChainType::REGTEST);

    // Hidden Options
    std::vector<std::string> hidden_args = {
        "-dbcrashratio", "-forcecompactdb",
        // GUI args. These will be overwritten by SetupUIArgs for the GUI
        "-choosedatadir", "-lang=<lang>", "-min", "-resetguisettings", "-splash", "-uiplatform"};

    argsman.AddArg("-version", "Print version and exit", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
#if HAVE_SYSTEM
    argsman.AddArg("-alertnotify=<cmd>", "Execute command when an alert is raised (%s in cmd is replaced by message)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
#endif
    argsman.AddArg("-assumevalid=<hex>", strprintf("If this block is in the chain assume that it and its ancestors are valid and potentially skip their script verification (0 to verify all, default: %s, testnet3: %s, testnet4: %s, signet: %s)", defaultChainParams->GetConsensus().defaultAssumeValid.GetHex(), testnetChainParams->GetConsensus().defaultAssumeValid.GetHex(), testnet4ChainParams->GetConsensus().defaultAssumeValid.GetHex(), signetChainParams->GetConsensus().defaultAssumeValid.GetHex()), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-blocksdir=<dir>", "Specify directory to hold blocks subdirectory for *.dat files (default: <datadir>)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-blocksxor",
                   strprintf("Whether an XOR-key applies to blocksdir *.dat files. "
                             "The created XOR-key will be zeros for an existing blocksdir or when `-blocksxor=0` is "
                             "set, and random for a freshly initialized blocksdir. "
                             "(default: %u)",
                             kernel::DEFAULT_XOR_BLOCKSDIR),
                   ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-fastprune", "Use smaller block files and lower minimum prune height for testing purposes", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-blocksonly", strprintf("Whether to reject transactions from network peers. Disables automatic broadcast and rebroadcast of transactions, unless the source peer has the 'forcerelay' permission. RPC transactions are not affected. (default: %u)", DEFAULT_BLOCKSONLY), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-conf=<file>", strprintf("Specify path to read-only configuration file. Relative paths will be prefixed by datadir location (only useable from command line, not configuration file) (default: %s)", BITCOIN_CONF_FILENAME), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-datadir=<dir>", "Specify data directory", ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION, OptionsCategory::OPTIONS);
    argsman.AddArg("-dbbatchsize", strprintf("Maximum database write batch size in bytes (default: %u)", nDefaultDbBatchSize), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::OPTIONS);
    argsman.AddArg("-dbcache=<n>", strprintf("Maximum database cache size <n> MiB (minimum %d, default: %d). Make sure you have enough RAM. In addition, unused memory allocated to the mempool is shared with this cache (see -maxmempool).", MIN_DB_CACHE >> 20, DEFAULT_DB_CACHE >> 20), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-allowignoredconf", strprintf("For backwards compatibility, treat an unused %s file in the datadir as a warning, not an error.", BITCOIN_CONF_FILENAME), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-loadblock=<file>", "Imports blocks from external file on startup", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-maxmempool=<n>", strprintf("Keep the transaction memory pool below <n> megabytes (default: %u)", DEFAULT_MAX_MEMPOOL_SIZE_MB), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    // TODO: remove in v31.0
    argsman.AddArg("-maxorphantx=<n>", strprintf("(Removed option, see release notes)"), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-mempoolexpiry=<n>", strprintf("Do not keep transactions in the mempool longer than <n> hours (default: %u)", DEFAULT_MEMPOOL_EXPIRY_HOURS), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-minimumchainwork=<hex>", strprintf("Minimum work assumed to exist on a valid chain in hex (default: %s, testnet3: %s, testnet4: %s, signet: %s)", defaultChainParams->GetConsensus().nMinimumChainWork.GetHex(), testnetChainParams->GetConsensus().nMinimumChainWork.GetHex(), testnet4ChainParams->GetConsensus().nMinimumChainWork.GetHex(), signetChainParams->GetConsensus().nMinimumChainWork.GetHex()), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::OPTIONS);
    argsman.AddArg("-par=<n>", strprintf("Set the number of script verification threads (0 = auto, up to %d, <0 = leave that many cores free, default: %d)",
        MAX_SCRIPTCHECK_THREADS, DEFAULT_SCRIPTCHECK_THREADS), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-persistmempool", strprintf("Whether to save the mempool on shutdown and load on restart (default: %u)", DEFAULT_PERSIST_MEMPOOL), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-persistmempoolv1",
                   strprintf("Whether a mempool.dat file created by -persistmempool or the savemempool RPC will be written in the legacy format "
                             "(version 1) or the current format (version 2). This temporary option will be removed in the future. (default: %u)",
                             DEFAULT_PERSIST_V1_DAT),
                   ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-pid=<file>", strprintf("Specify pid file. Relative paths will be prefixed by a net-specific datadir location. (default: %s)", BITCOIN_PID_FILENAME), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-prune=<n>", strprintf("Reduce storage requirements by enabling pruning (deleting) of old blocks. This allows the pruneblockchain RPC to be called to delete specific blocks and enables automatic pruning of old blocks if a target size in MiB is provided. This mode is incompatible with -txindex. "
            "Warning: Reverting this setting requires re-downloading the entire blockchain. "
            "(default: 0 = disable pruning blocks, 1 = allow manual pruning via RPC, >=%u = automatically prune block files to stay under the specified target size in MiB)", MIN_DISK_SPACE_FOR_BLOCK_FILES / 1024 / 1024), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-reindex", "If enabled, wipe chain state and block index, and rebuild them from blk*.dat files on disk. Also wipe and rebuild other optional indexes that are active. If an assumeutxo snapshot was loaded, its chainstate will be wiped as well. The snapshot can then be reloaded via RPC.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-reindex-chainstate", "If enabled, wipe chain state, and rebuild it from blk*.dat files on disk. If an assumeutxo snapshot was loaded, its chainstate will be wiped as well. The snapshot can then be reloaded via RPC.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-settings=<file>", strprintf("Specify path to dynamic settings data file. Can be disabled with -nosettings. File is written at runtime and not meant to be edited by users (use %s instead for custom settings). Relative paths will be prefixed by datadir location. (default: %s)", BITCOIN_CONF_FILENAME, BITCOIN_SETTINGS_FILENAME), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
#if HAVE_SYSTEM
    argsman.AddArg("-startupnotify=<cmd>", "Execute command on startup.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-shutdownnotify=<cmd>", "Execute command immediately before beginning shutdown. The need for shutdown may be urgent, so be careful not to delay it long (if the command doesn't require interaction with the server, consider having it fork into the background).", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
#endif
    argsman.AddArg("-timeout=<n>", strprintf("Specify socket connection timeout in milliseconds. If an initial attempt to connect is unsuccessful after this amount of time, drop it (minimum: 1, default: %d)", DEFAULT_CONNECT_TIMEOUT), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);

    argsman.AddArg("-checkblocks=<n>", strprintf("How many blocks to check at startup (default: %u, 0 = all)", DEFAULT_CHECKBLOCKS), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-checklevel=<n>", strprintf("How thorough the block verification of -checkblocks is: %s (0-4, default: %u)", Join(CHECKLEVEL_DOC, ", "), DEFAULT_CHECKLEVEL), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-checkblockindex", strprintf("Do a consistency check for the block tree, chainstate, and other validation data structures every <n> operations. Use 0 to disable. (default: %u, regtest: %u)", defaultChainParams->DefaultConsistencyChecks(), regtestChainParams->DefaultConsistencyChecks()), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-checkmempool=<n>", strprintf("Run mempool consistency checks every <n> transactions. Use 0 to disable. (default: %u, regtest: %u)", defaultChainParams->DefaultConsistencyChecks(), regtestChainParams->DefaultConsistencyChecks()), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    // Checkpoints were removed. We keep `-checkpoints` as a hidden arg to display a more user friendly error when set.
    argsman.AddArg("-checkpoints", "", ArgsManager::ALLOW_ANY, OptionsCategory::HIDDEN);
    argsman.AddArg("-stopafterblockimport", strprintf("Stop running after importing blocks from disk (default: %u)", DEFAULT_STOPAFTERBLOCKIMPORT), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-stopatheight", strprintf("Stop running after reaching the given height in the main chain (default: %u)", DEFAULT_STOPATHEIGHT), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-limitancestorcount=<n>", strprintf("Do not accept transactions if number of in-mempool ancestors is <n> or more (default: %u)", DEFAULT_ANCESTOR_LIMIT), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-limitancestorsize=<n>", strprintf("Do not accept transactions whose size with all in-mempool ancestors exceeds <n> kilobytes (default: %u)", DEFAULT_ANCESTOR_SIZE_LIMIT_KVB), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-limitdescendantcount=<n>", strprintf("Do not accept transactions if any ancestor would have <n> or more in-mempool descendants (default: %u)", DEFAULT_DESCENDANT_LIMIT), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-limitdescendantsize=<n>", strprintf("Do not accept transactions if any ancestor would have more than <n> kilobytes of in-mempool descendants (default: %u).", DEFAULT_DESCENDANT_SIZE_LIMIT_KVB), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-test=<option>", "Pass a test-only option. Options include : " + Join(TEST_OPTIONS_DOC, ", ") + ".", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-mocktime=<n>", "Replace actual time with " + UNIX_EPOCH_TIME + " (default: 0)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-maxsigcachesize=<n>", strprintf("Limit sum of signature cache and script execution cache sizes to <n> MiB (default: %u)", DEFAULT_VALIDATION_CACHE_BYTES >> 20), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-maxtipage=<n>",
                   strprintf("Maximum tip age in seconds to consider node in initial block download (default: %u)",
                             Ticks<std::chrono::seconds>(DEFAULT_MAX_TIP_AGE)),
                   ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-printpriority", strprintf("Log transaction fee rate in %s/kvB when mining blocks (default: %u)", CURRENCY_UNIT, DEFAULT_PRINT_MODIFIED_FEE), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);

    SetupChainParamsBaseOptions(argsman);

    argsman.AddArg("-acceptnonstdtxn", strprintf("Relay and mine \"non-standard\" transactions (test networks only; default: %u)", DEFAULT_ACCEPT_NON_STD_TXN), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::NODE_RELAY);
    argsman.AddArg("-incrementalrelayfee=<amt>", strprintf("Fee rate (in %s/kvB) used to define cost of relay, used for mempool limiting and replacement policy. (default: %s)", CURRENCY_UNIT, FormatMoney(DEFAULT_INCREMENTAL_RELAY_FEE)), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::NODE_RELAY);
    argsman.AddArg("-dustrelayfee=<amt>", strprintf("Fee rate (in %s/kvB) used to define dust, the value of an output such that it will cost more than its value in fees at this fee rate to spend it. (default: %s)", CURRENCY_UNIT, FormatMoney(DUST_RELAY_TX_FEE)), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::NODE_RELAY);
    argsman.AddArg("-bytespersigop", strprintf("Equivalent bytes per sigop in transactions for relay and mining (default: %u)", DEFAULT_BYTES_PER_SIGOP), ArgsManager::ALLOW_ANY, OptionsCategory::NODE_RELAY);
    argsman.AddArg("-datacarrier", strprintf("(DEPRECATED) Relay and mine data carrier transactions (default: %u)", DEFAULT_ACCEPT_DATACARRIER), ArgsManager::ALLOW_ANY, OptionsCategory::NODE_RELAY);
    argsman.AddArg("-datacarriersize",
                   strprintf("(DEPRECATED) Relay and mine transactions whose data-carrying raw scriptPubKeys in aggregate "
                             "are of this size or less, allowing multiple outputs (default: %u)",
                             MAX_OP_RETURN_RELAY),
                   ArgsManager::ALLOW_ANY, OptionsCategory::NODE_RELAY);
    argsman.AddArg("-permitbaremultisig", strprintf("Relay transactions creating non-P2SH multisig outputs (default: %u)", DEFAULT_PERMIT_BAREMULTISIG), ArgsManager::ALLOW_ANY,
                   OptionsCategory::NODE_RELAY);
    argsman.AddArg("-minrelaytxfee=<amt>", strprintf("Fees (in %s/kvB) smaller than this are considered zero fee for relaying, mining and transaction creation (default: %s)",
        CURRENCY_UNIT, FormatMoney(DEFAULT_MIN_RELAY_TX_FEE)), ArgsManager::ALLOW_ANY, OptionsCategory::NODE_RELAY);

    argsman.AddArg("-blockmaxweight=<n>", strprintf("Set maximum BIP141 block weight (default: %d)", DEFAULT_BLOCK_MAX_WEIGHT), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::BLOCK_CREATION);
    argsman.AddArg("-blockreservedweight=<n>", strprintf("Reserve space for the fixed-size block header plus the largest coinbase transaction the mining software may add to the block. (default: %d).", DEFAULT_BLOCK_RESERVED_WEIGHT), ArgsManager::ALLOW_ANY, OptionsCategory::BLOCK_CREATION);
    argsman.AddArg("-blockmintxfee=<amt>", strprintf("Set lowest fee rate (in %s/kvB) for transactions to be included in block creation. (default: %s)", CURRENCY_UNIT, FormatMoney(DEFAULT_BLOCK_MIN_TX_FEE)), ArgsManager::ALLOW_ANY, OptionsCategory::BLOCK_CREATION);
    argsman.AddArg("-blockversion=<n>", "Override block version to test forking scenarios", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::BLOCK_CREATION);
    argsman.AddArg("-coinbaselocktime", strprintf("Set nLockTime to the current block height and nSequence to enforce it (default: %d)", DEFAULT_COINBASE_LOCKTIME), ArgsManager::ALLOW_ANY, OptionsCategory::BLOCK_CREATION);

    if (can_listen_ipc) {
        argsman.AddArg("-ipcbind=<address>", "Bind to Unix socket address and listen for incoming connections. Valid address values are \"unix\" to listen on the default path, <datadir>/node.sock, or \"unix:/custom/path\" to specify a custom path. Can be specified multiple times to listen on multiple paths. Default behavior is not to listen on any path. If relative paths are specified, they are interpreted relative to the network data directory. If paths include any parent directory components and the parent directories do not exist, they will be created.", ArgsManager::ALLOW_ANY, OptionsCategory::IPC);
    }

#if HAVE_DECL_FORK
    argsman.AddArg("-daemon", strprintf("Run in the background as a daemon and accept commands (default: %d)", DEFAULT_DAEMON), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
#else
    hidden_args.emplace_back("-daemon");
#endif

    // Add the hidden options
    argsman.AddHiddenArgs(hidden_args);
}

#if HAVE_SYSTEM
static void StartupNotify(const ArgsManager& args)
{
    std::string cmd = args.GetArg("-startupnotify", "");
    if (!cmd.empty()) {
        std::thread t(runCommand, cmd);
        t.detach(); // thread runs free
    }
}
#endif

// Parameter interaction based on rules
void InitParameterInteraction(ArgsManager& args)
{
    if (args.GetBoolArg("-blocksonly", DEFAULT_BLOCKSONLY)) {
        // disable whitelistrelay in blocksonly mode
        if (args.SoftSetBoolArg("-whitelistrelay", false))
            LogInfo("parameter interaction: -blocksonly=1 -> setting -whitelistrelay=0\n");
        // Reduce default mempool size in blocksonly mode to avoid unexpected resource usage
        if (args.SoftSetArg("-maxmempool", ToString(DEFAULT_BLOCKSONLY_MAX_MEMPOOL_SIZE_MB)))
            LogInfo("parameter interaction: -blocksonly=1 -> setting -maxmempool=%d\n", DEFAULT_BLOCKSONLY_MAX_MEMPOOL_SIZE_MB);
    }
}

/**
 * Initialize global loggers.
 *
 * Note that this is called very early in the process lifetime, so you should be
 * careful about what global state you rely on here.
 */
void InitLogging(const ArgsManager& args)
{
    init::SetLoggingOptions(args);
    init::LogPackageVersion();
}

namespace { // Variables internal to initialization process only

int nMaxConnections;
int available_fds;
ServiceFlags g_local_services = ServiceFlags(NODE_NETWORK_LIMITED | NODE_WITNESS);
std::set<BlockFilterType> g_enabled_filter_types;

} // namespace

[[noreturn]] static void new_handler_terminate()
{
    // Rather than throwing std::bad-alloc if allocation fails, terminate
    // immediately to (try to) avoid chain corruption.
    // Since logging may itself allocate memory, set the handler directly
    // to terminate first.
    std::set_new_handler(std::terminate);
    LogError("Out of memory. Terminating.\n");

    // The log was successful, terminate now.
    std::terminate();
};

bool AppInitBasicSetup(const ArgsManager& args, std::atomic<int>& exit_status)
{
    // ********************************************************* Step 1: setup
#ifdef _MSC_VER
    // Turn off Microsoft heap dump noise
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFileA("NUL", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, 0));
    // Disable confusing "helpful" text message on abort, Ctrl-C
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
#ifdef WIN32
    // Enable heap terminate-on-corruption
    HeapSetInformation(nullptr, HeapEnableTerminationOnCorruption, nullptr, 0);
#endif
    if (!SetupNetworking()) {
        return InitError(Untranslated("Initializing networking failed."));
    }

#ifndef WIN32
    // Clean shutdown on SIGTERM
    registerSignalHandler(SIGTERM, HandleSIGTERM);
    registerSignalHandler(SIGINT, HandleSIGTERM);

    // Reopen debug.log on SIGHUP
    registerSignalHandler(SIGHUP, HandleSIGHUP);

    // Ignore SIGPIPE, otherwise it will bring the daemon down if the client closes unexpectedly
    signal(SIGPIPE, SIG_IGN);
#else
    SetConsoleCtrlHandler(consoleCtrlHandler, true);
#endif

    std::set_new_handler(new_handler_terminate);

    return true;
}

bool AppInitParameterInteraction(const ArgsManager& args)
{
    const CChainParams& chainparams = Params();
    // ********************************************************* Step 2: parameter interactions

    // also see: InitParameterInteraction()

    // We removed checkpoints but keep the option to warn users who still have it in their config.
    if (args.IsArgSet("-checkpoints")) {
        InitWarning(_("Option '-checkpoints' is set but checkpoints were removed. This option has no effect."));
    }

    if (args.IsArgSet("-datacarriersize") || args.IsArgSet("-datacarrier")) {
        InitWarning(_("Options '-datacarrier' or '-datacarriersize' are set but are marked as deprecated. They will be removed in a future version."));
    }

    // We no longer limit the orphanage based on number of transactions but keep the option to warn users who still have it in their config.
    if (args.IsArgSet("-maxorphantx")) {
        InitWarning(_("Option '-maxorphantx' is set but no longer has any effect (see release notes). Please remove it from your configuration."));
    }

    // Error if network-specific options (-addnode, -connect, etc) are
    // specified in default section of config file, but not overridden
    // on the command line or in this chain's section of the config file.
    ChainType chain = args.GetChainType();
    if (chain == ChainType::SIGNET) {
        LogInfo("Signet derived magic (message start): %s", HexStr(chainparams.MessageStart()));
    }
    bilingual_str errors;
    for (const auto& arg : args.GetUnsuitableSectionOnlyArgs()) {
        errors += strprintf(_("Config setting for %s only applied on %s network when in [%s] section."), arg, ChainTypeToString(chain), ChainTypeToString(chain)) + Untranslated("\n");
    }

    if (!errors.empty()) {
        return InitError(errors);
    }

    // Testnet3 deprecation warning
    if (chain == ChainType::TESTNET) {
        LogInfo("Warning: Support for testnet3 is deprecated and will be removed in an upcoming release. Consider switching to testnet4.\n");
    }

    // Warn if unrecognized section name are present in the config file.
    bilingual_str warnings;
    for (const auto& section : args.GetUnrecognizedSections()) {
        warnings += Untranslated(strprintf("%s:%i ", section.m_file, section.m_line)) + strprintf(_("Section [%s] is not recognized."), section.m_name) + Untranslated("\n");
    }

    if (!warnings.empty()) {
        InitWarning(warnings);
    }

    if (!fs::is_directory(args.GetBlocksDirPath())) {
        return InitError(strprintf(_("Specified blocks directory \"%s\" does not exist."), args.GetArg("-blocksdir", "")));
    }

    if (args.GetIntArg("-prune", 0)) {
        if (args.GetBoolArg("-reindex-chainstate", false)) {
            return InitError(_("Prune mode is incompatible with -reindex-chainstate. Use full -reindex instead."));
        }
    }

    // ********************************************************* Step 3: parameter-to-internal-flags
    if (auto result{init::SetLoggingCategories(args)}; !result) return InitError(util::ErrorString(result));
    if (auto result{init::SetLoggingLevel(args)}; !result) return InitError(util::ErrorString(result));

    nConnectTimeout = args.GetIntArg("-timeout", DEFAULT_CONNECT_TIMEOUT);
    if (nConnectTimeout <= 0) {
        nConnectTimeout = DEFAULT_CONNECT_TIMEOUT;
    }

    if (const auto arg{args.GetArg("-blockmintxfee")}) {
        if (!ParseMoney(*arg)) {
            return InitError(AmountErrMsg("blockmintxfee", *arg));
        }
    }

    {
        const auto max_block_weight = args.GetIntArg("-blockmaxweight", DEFAULT_BLOCK_MAX_WEIGHT);
        if (max_block_weight > MAX_BLOCK_WEIGHT) {
            return InitError(strprintf(_("Specified -blockmaxweight (%d) exceeds consensus maximum block weight (%d)"), max_block_weight, MAX_BLOCK_WEIGHT));
        }
    }

    {
        const auto block_reserved_weight = args.GetIntArg("-blockreservedweight", DEFAULT_BLOCK_RESERVED_WEIGHT);
        if (block_reserved_weight > MAX_BLOCK_WEIGHT) {
            return InitError(strprintf(_("Specified -blockreservedweight (%d) exceeds consensus maximum block weight (%d)"), block_reserved_weight, MAX_BLOCK_WEIGHT));
        }
        if (block_reserved_weight < MINIMUM_BLOCK_RESERVED_WEIGHT) {
            return InitError(strprintf(_("Specified -blockreservedweight (%d) is lower than minimum safety value of (%d)"), block_reserved_weight, MINIMUM_BLOCK_RESERVED_WEIGHT));
        }
    }

    nBytesPerSigOp = args.GetIntArg("-bytespersigop", nBytesPerSigOp);

    // Option to startup with mocktime set (used for regression testing):
    if (const auto mocktime{args.GetIntArg("-mocktime")}) {
        SetMockTime(std::chrono::seconds{*mocktime});
    }

    const std::vector<std::string> test_options = args.GetArgs("-test");
    if (!test_options.empty()) {
        if (chainparams.GetChainType() != ChainType::REGTEST) {
            return InitError(Untranslated("-test=<option> can only be used with regtest"));
        }
        for (const std::string& option : test_options) {
            auto it = std::find_if(TEST_OPTIONS_DOC.begin(), TEST_OPTIONS_DOC.end(), [&option](const std::string& doc_option) {
                size_t pos = doc_option.find(" (");
                return (pos != std::string::npos) && (doc_option.substr(0, pos) == option);
            });
            if (it == TEST_OPTIONS_DOC.end()) {
                InitWarning(strprintf(_("Unrecognised option \"%s\" provided in -test=<option>."), option));
            }
        }
    }

    // Also report errors from parsing before daemonization
    {
        kernel::Notifications notifications{};
        ChainstateManager::Options chainman_opts_dummy{
            .chainparams = chainparams,
            .datadir = args.GetDataDirNet(),
            .notifications = notifications,
        };
        auto chainman_result{ApplyArgsManOptions(args, chainman_opts_dummy)};
        if (!chainman_result) {
            return InitError(util::ErrorString(chainman_result));
        }
        BlockManager::Options blockman_opts_dummy{
            .chainparams = chainman_opts_dummy.chainparams,
            .blocks_dir = args.GetBlocksDirPath(),
            .notifications = chainman_opts_dummy.notifications,
            .block_tree_db_params = DBParams{
                .path = args.GetDataDirNet() / "blocks" / "index",
                .cache_bytes = 0,
            },
        };
        auto blockman_result{ApplyArgsManOptions(args, blockman_opts_dummy)};
        if (!blockman_result) {
            return InitError(util::ErrorString(blockman_result));
        }
        CTxMemPool::Options mempool_opts{};
        auto mempool_result{ApplyArgsManOptions(args, chainparams, mempool_opts)};
        if (!mempool_result) {
            return InitError(util::ErrorString(mempool_result));
        }
    }

    return true;
}

static bool LockDirectory(const fs::path& dir, bool probeOnly)
{
    // Make sure only a single process is using the directory.
    switch (util::LockDirectory(dir, ".lock", probeOnly)) {
    case util::LockResult::ErrorWrite:
        return InitError(strprintf(_("Cannot write to directory '%s'; check permissions."), fs::PathToString(dir)));
    case util::LockResult::ErrorLock:
        return InitError(strprintf(_("Cannot obtain a lock on directory %s. %s is probably already running."), fs::PathToString(dir), CLIENT_NAME));
    case util::LockResult::Success: return true;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}
static bool LockDirectories(bool probeOnly)
{
    return LockDirectory(gArgs.GetDataDirNet(), probeOnly) && \
           LockDirectory(gArgs.GetBlocksDirPath(), probeOnly);
}

bool AppInitSanityChecks(const kernel::Context& kernel)
{
    // ********************************************************* Step 4: sanity checks
    auto result{kernel::SanityChecks(kernel)};
    if (!result) {
        InitError(util::ErrorString(result));
        return InitError(strprintf(_("Initialization sanity check failed. %s is shutting down."), CLIENT_NAME));
    }

    if (!ECC_InitSanityCheck()) {
        return InitError(strprintf(_("Elliptic curve cryptography sanity check failure. %s is shutting down."), CLIENT_NAME));
    }

    // Probe the directory locks to give an early error message, if possible
    // We cannot hold the directory locks here, as the forking for daemon() hasn't yet happened,
    // and a fork will cause weird behavior to them.
    return LockDirectories(true);
}

bool AppInitLockDirectories()
{
    // After daemonization get the directory locks again and hold on to them until exit
    // This creates a slight window for a race condition to happen, however this condition is harmless: it
    // will at most make us exit without printing a message to console.
    if (!LockDirectories(false)) {
        // Detailed error printed inside LockDirectory
        return false;
    }
    return true;
}

bool AppInitInterfaces(NodeContext& node)
{
    node.chain = node.init->makeChain();
    node.mining = node.init->makeMining();
    return true;
}

// A GUI user may opt to retry once with do_reindex set if there is a failure during chainstate initialization.
// The function therefore has to support re-entry.
static ChainstateLoadResult InitAndLoadChainstate(
    NodeContext& node,
    bool do_reindex,
    const bool do_reindex_chainstate,
    const kernel::CacheSizes& cache_sizes,
    const ArgsManager& args)
{
    // This function may be called twice, so any dirty state must be reset.
    node.notifications.reset(); // Drop state, such as a cached tip block
    node.mempool.reset();
    node.chainman.reset(); // Drop state, such as an initialized m_block_tree_db

    const CChainParams& chainparams = Params();

    Assert(!node.notifications); // Was reset above
    node.notifications = std::make_unique<KernelNotifications>(Assert(node.shutdown_request), node.exit_status, *Assert(node.warnings));
    ReadNotificationArgs(args, *node.notifications);

    CTxMemPool::Options mempool_opts{
        .check_ratio = chainparams.DefaultConsistencyChecks() ? 1 : 0,
        .signals = node.validation_signals.get(),
    };
    Assert(ApplyArgsManOptions(args, chainparams, mempool_opts)); // no error can happen, already checked in AppInitParameterInteraction
    bilingual_str mempool_error;
    Assert(!node.mempool); // Was reset above
    node.mempool = std::make_unique<CTxMemPool>(mempool_opts, mempool_error);
    if (!mempool_error.empty()) {
        return {ChainstateLoadStatus::FAILURE_FATAL, mempool_error};
    }
    LogInfo("* Using %.1f MiB for in-memory UTXO set (plus up to %.1f MiB of unused mempool space)",
            cache_sizes.coins * (1.0 / 1024 / 1024),
            mempool_opts.max_size_bytes * (1.0 / 1024 / 1024));
    ChainstateManager::Options chainman_opts{
        .chainparams = chainparams,
        .datadir = args.GetDataDirNet(),
        .notifications = *node.notifications,
        .signals = node.validation_signals.get(),
    };
    Assert(ApplyArgsManOptions(args, chainman_opts)); // no error can happen, already checked in AppInitParameterInteraction

    BlockManager::Options blockman_opts{
        .chainparams = chainman_opts.chainparams,
        .blocks_dir = args.GetBlocksDirPath(),
        .notifications = chainman_opts.notifications,
        .block_tree_db_params = DBParams{
            .path = args.GetDataDirNet() / "blocks" / "index",
            .cache_bytes = cache_sizes.block_tree_db,
            .wipe_data = do_reindex,
        },
    };
    Assert(ApplyArgsManOptions(args, blockman_opts)); // no error can happen, already checked in AppInitParameterInteraction

    // Creating the chainstate manager internally creates a BlockManager, opens
    // the blocks tree db, and wipes existing block files in case of a reindex.
    // The coinsdb is opened at a later point on LoadChainstate.
    Assert(!node.chainman); // Was reset above
    try {
        node.chainman = std::make_unique<ChainstateManager>(*Assert(node.shutdown_signal), chainman_opts, blockman_opts);
    } catch (dbwrapper_error& e) {
        LogError("%s", e.what());
        return {ChainstateLoadStatus::FAILURE, _("Error opening block database")};
    } catch (std::exception& e) {
        return {ChainstateLoadStatus::FAILURE_FATAL, Untranslated(strprintf("Failed to initialize ChainstateManager: %s", e.what()))};
    }
    ChainstateManager& chainman = *node.chainman;
    if (chainman.m_interrupt) return {ChainstateLoadStatus::INTERRUPTED, {}};

    // This is defined and set here instead of inline in validation.h to avoid a hard
    // dependency between validation and index/base, since the latter is not in
    // libbitcoinkernel.
    chainman.snapshot_download_completed = [&node]() {
        if (!node.chainman->m_blockman.IsPruneMode()) {
            LogInfo("[snapshot] re-enabling NODE_NETWORK services");
        }
    };
    node::ChainstateLoadOptions options;
    options.mempool = Assert(node.mempool.get());
    options.wipe_chainstate_db = do_reindex || do_reindex_chainstate;
    options.prune = chainman.m_blockman.IsPruneMode();
    options.check_blocks = args.GetIntArg("-checkblocks", DEFAULT_CHECKBLOCKS);
    options.check_level = args.GetIntArg("-checklevel", DEFAULT_CHECKLEVEL);
    options.require_full_verification = args.IsArgSet("-checkblocks") || args.IsArgSet("-checklevel");

    auto catch_exceptions = [](auto&& f) -> ChainstateLoadResult {
        try {
            return f();
        } catch (const std::exception& e) {
            LogError("%s\n", e.what());
            return std::make_tuple(node::ChainstateLoadStatus::FAILURE, _("Error loading databases"));
        }
    };
    auto [status, error] = catch_exceptions([&] { return LoadChainstate(chainman, cache_sizes, options); });
    if (status == node::ChainstateLoadStatus::SUCCESS) {
        if (chainman.m_blockman.m_have_pruned && options.check_blocks > MIN_BLOCKS_TO_KEEP) {
            LogWarning("pruned datadir may not have more than %d blocks; only checking available blocks\n",
                       MIN_BLOCKS_TO_KEEP);
        }
        std::tie(status, error) = catch_exceptions([&] { return VerifyLoadedChainstate(chainman, options); });
        if (status == node::ChainstateLoadStatus::SUCCESS) {
            LogInfo("Block index and chainstate loaded");
        }
    }
    return {status, error};
};

bool AppInitMain(NodeContext& node, interfaces::BlockAndHeaderTipInfo* tip_info)
{
    const ArgsManager& args = *Assert(node.args);
    const CChainParams& chainparams = Params();

    // ********************************************************* Step 4a: application initialization
    if (!CreatePidFile(args)) {
        // Detailed error printed inside CreatePidFile().
        return false;
    }
    if (!init::StartLogging(args)) {
        // Detailed error printed inside StartLogging().
        return false;
    }

    LogInfo("Using at most %i automatic connections (%i file descriptors available)", nMaxConnections, available_fds);

    // Warn about relative -datadir path.
    if (args.IsArgSet("-datadir") && !args.GetPathArg("-datadir").is_absolute()) {
        LogPrintf("Warning: relative datadir option '%s' specified, which will be interpreted relative to the "
                  "current working directory '%s'. This is fragile, because if bitcoin is started in the future "
                  "from a different location, it will be unable to locate the current data files. There could "
                  "also be data loss if bitcoin is started while in a temporary directory.\n",
                  args.GetArg("-datadir", ""), fs::PathToString(fs::current_path()));
    }

    assert(!node.scheduler);
    node.scheduler = std::make_unique<CScheduler>();
    auto& scheduler = *node.scheduler;

    // Start the lightweight task scheduler thread
    scheduler.m_service_thread = std::thread(util::TraceThread, "scheduler", [&] { scheduler.serviceQueue(); });

    // Gather some entropy once per minute.
    scheduler.scheduleEvery([]{
        RandAddPeriodic();
    }, std::chrono::minutes{1});

    // Check disk space every 5 minutes to avoid db corruption.
    scheduler.scheduleEvery([&args, &node]{
        constexpr uint64_t min_disk_space = 50 << 20; // 50 MB
        if (!CheckDiskSpace(args.GetBlocksDirPath(), min_disk_space)) {
            LogError("Shutting down due to lack of disk space!\n");
            if (!(Assert(node.shutdown_request))()) {
                LogError("Failed to send shutdown signal after disk space check\n");
            }
        }
    }, std::chrono::minutes{5});

    if (args.GetBoolArg("-logratelimit", BCLog::DEFAULT_LOGRATELIMIT)) {
        LogInstance().SetRateLimiting(BCLog::LogRateLimiter::Create(
            [&scheduler](auto func, auto window) { scheduler.scheduleEvery(std::move(func), window); },
            BCLog::RATELIMIT_MAX_BYTES,
            BCLog::RATELIMIT_WINDOW));
    } else {
        LogInfo("Log rate limiting disabled");
    }

    if (interfaces::Ipc* ipc = node.init->ipc()) {
        for (std::string address : gArgs.GetArgs("-ipcbind")) {
            try {
                ipc->listenAddress(address);
            } catch (const std::exception& e) {
                return InitError(Untranslated(strprintf("Unable to bind to IPC address '%s'. %s", address, e.what())));
            }
            LogInfo("Listening for IPC requests on address %s", address);
        }
    }

    // ********************************************************* Step 7: load block chain

    // cache size calculations
    const auto [index_cache_sizes, kernel_cache_sizes] = CalculateCacheSizes(args, g_enabled_filter_types.size());

    LogInfo("Cache configuration:");
    LogInfo("* Using %.1f MiB for block index database", kernel_cache_sizes.block_tree_db * (1.0 / 1024 / 1024));
    LogInfo("* Using %.1f MiB for chain state database", kernel_cache_sizes.coins_db * (1.0 / 1024 / 1024));

    assert(!node.mempool);
    assert(!node.chainman);

    bool do_reindex{args.GetBoolArg("-reindex", false)};
    const bool do_reindex_chainstate{args.GetBoolArg("-reindex-chainstate", false)};

    // Chainstate initialization and loading may be retried once with reindexing by GUI users
    auto [status, error] = InitAndLoadChainstate(
        node,
        do_reindex,
        do_reindex_chainstate,
        kernel_cache_sizes,
        args);
    if (status == ChainstateLoadStatus::FAILURE && !do_reindex && !ShutdownRequested(node)) {
        // suggest a reindex
        bool do_retry{HasTestOption(args, "reindex_after_failure_noninteractive_yes")};
        if (!do_retry) {
            return false;
        }
        do_reindex = true;
        if (!Assert(node.shutdown_signal)->reset()) {
            LogError("Internal error: failed to reset shutdown signal.\n");
        }
        std::tie(status, error) = InitAndLoadChainstate(
            node,
            do_reindex,
            do_reindex_chainstate,
            kernel_cache_sizes,
            args);
    }
    if (status != ChainstateLoadStatus::SUCCESS && status != ChainstateLoadStatus::INTERRUPTED) {
        return InitError(error);
    }

    // As LoadBlockIndex can take several minutes, it's possible the user
    // requested to kill the GUI during the last operation. If so, exit.
    if (ShutdownRequested(node)) {
        LogInfo("Shutdown requested. Exiting.");
        return false;
    }

    ChainstateManager& chainman = *Assert(node.chainman);
    auto& kernel_notifications{*Assert(node.notifications)};

    // ********************************************************* Step 9: load wallet
    for (const auto& client : node.chain_clients) {
        if (!client->load()) {
            return false;
        }
    }

    // ********************************************************* Step 10: data directory maintenance

    // if pruning, perform the initial blockstore prune
    // after any wallet rescanning has taken place.
    if (chainman.m_blockman.IsPruneMode()) {
        if (chainman.m_blockman.m_blockfiles_indexed) {
            LOCK(cs_main);
            for (Chainstate* chainstate : chainman.GetAll()) {
                chainstate->PruneAndFlush();
            }
        }
    } else {
        // Prior to setting NODE_NETWORK, check if we can provide historical blocks.
        if (!WITH_LOCK(chainman.GetMutex(), return chainman.BackgroundSyncInProgress())) {
            LogInfo("Setting NODE_NETWORK on non-prune mode");
            g_local_services = ServiceFlags(g_local_services | NODE_NETWORK);
        } else {
            LogInfo("Running node in NODE_NETWORK_LIMITED mode until snapshot background sync completes");
        }
    }

    // ********************************************************* Step 11: import blocks

    if (!CheckDiskSpace(args.GetDataDirNet())) {
        InitError(strprintf(_("Error: Disk space is low for %s"), fs::quoted(fs::PathToString(args.GetDataDirNet()))));
        return false;
    }
    if (!CheckDiskSpace(args.GetBlocksDirPath())) {
        InitError(strprintf(_("Error: Disk space is low for %s"), fs::quoted(fs::PathToString(args.GetBlocksDirPath()))));
        return false;
    }

    int chain_active_height = WITH_LOCK(cs_main, return chainman.ActiveChain().Height());

    // On first startup, warn on low block storage space
    if (!do_reindex && !do_reindex_chainstate && chain_active_height <= 1) {
        uint64_t assumed_chain_bytes{chainparams.AssumedBlockchainSize() * 1024 * 1024 * 1024};
        uint64_t additional_bytes_needed{
            chainman.m_blockman.IsPruneMode() ?
                std::min(chainman.m_blockman.GetPruneTarget(), assumed_chain_bytes) :
                assumed_chain_bytes};

        if (!CheckDiskSpace(args.GetBlocksDirPath(), additional_bytes_needed)) {
            InitWarning(strprintf(_(
                    "Disk space for %s may not accommodate the block files. " \
                    "Approximately %u GB of data will be stored in this directory."
                ),
                fs::quoted(fs::PathToString(args.GetBlocksDirPath())),
                chainparams.AssumedBlockchainSize()
            ));
        }
    }

#ifdef __APPLE__
    auto check_and_warn_fs{[&](const fs::path& path, std::string_view desc) {
        const auto path_desc{strprintf("%s (\"%s\")", desc, fs::PathToString(path))};
        switch (GetFilesystemType(path)) {
        case FSType::EXFAT:
            InitWarning(strprintf(_("The %s path uses exFAT, which is known to have intermittent corruption problems on macOS. "
                "Move this directory to a different filesystem to avoid data loss."), path_desc));
            break;
        case FSType::ERROR:
            LogInfo("Failed to detect filesystem type for %s", path_desc);
            break;
        case FSType::OTHER:
            break;
        }
    }};

    check_and_warn_fs(args.GetDataDirNet(), "data directory");
    check_and_warn_fs(args.GetBlocksDirPath(), "blocks directory");
#endif

    std::vector<fs::path> vImportFiles;
    for (const std::string& strFile : args.GetArgs("-loadblock")) {
        vImportFiles.push_back(fs::PathFromString(strFile));
    }

    node.background_init_thread = std::thread(&util::TraceThread, "initload", [=, &chainman, &args, &node] {
        ScheduleBatchPriority();
        // Import blocks and ActivateBestChain()
        ImportBlocks(chainman, vImportFiles);
        if (args.GetBoolArg("-stopafterblockimport", DEFAULT_STOPAFTERBLOCKIMPORT)) {
            LogInfo("Stopping after block import");
            if (!(Assert(node.shutdown_request))()) {
                LogError("Failed to send shutdown signal after finishing block import\n");
            }
            return;
        }

        // Load mempool from disk
        if (auto* pool{chainman.ActiveChainstate().GetMempool()}) {
            LoadMempool(*pool, ShouldPersistMempool(args) ? MempoolPath(args) : fs::path{}, chainman.ActiveChainstate(), {});
            pool->SetLoadTried(!chainman.m_interrupt);
        }
    });

    /*
     * Wait for genesis block to be processed. Typically kernel_notifications.m_tip_block
     * has already been set by a call to LoadChainTip() in CompleteChainstateInitialization().
     * But this is skipped if the chainstate doesn't exist yet or is being wiped:
     *
     * 1. first startup with an empty datadir
     * 2. reindex
     * 3. reindex-chainstate
     *
     * In these case it's connected by a call to ActivateBestChain() in the initload thread.
     */
    {
        WAIT_LOCK(kernel_notifications.m_tip_block_mutex, lock);
        kernel_notifications.m_tip_block_cv.wait(lock, [&]() EXCLUSIVE_LOCKS_REQUIRED(kernel_notifications.m_tip_block_mutex) {
            return kernel_notifications.TipBlock() || ShutdownRequested(node);
        });
    }

    if (ShutdownRequested(node)) {
        return false;
    }

    // ********************************************************* Step 12: start node

    int64_t best_block_time{};
    {
        LOCK(chainman.GetMutex());
        const auto& tip{*Assert(chainman.ActiveTip())};
        LogInfo("block tree size = %u", chainman.BlockIndex().size());
        chain_active_height = tip.nHeight;
        best_block_time = tip.GetBlockTime();
        if (tip_info) {
            tip_info->block_height = chain_active_height;
            tip_info->block_time = best_block_time;
            tip_info->verification_progress = chainman.GuessVerificationProgress(&tip);
        }
        if (tip_info && chainman.m_best_header) {
            tip_info->header_height = chainman.m_best_header->nHeight;
            tip_info->header_time = chainman.m_best_header->GetBlockTime();
        }
    }
    LogInfo("nBestHeight = %d", chain_active_height);

    // ********************************************************* Step 13: finished

    for (const auto& client : node.chain_clients) {
        client->start(scheduler);
    }

#if HAVE_SYSTEM
    StartupNotify(args);
#endif

    return true;
}


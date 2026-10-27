// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/tx_collection.h>

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <common/args.h>
#include <memusage.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <node/blockstorage.h>
#include <node/miner.h>
#include <node/mining_types.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <sync.h>
#include <tinyformat.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/byte_units.h>
#include <util/check.h>
#include <util/expected.h>
#include <util/hasher.h>
#include <util/signalinterrupt.h>
#include <util/thread.h>
#include <util/threadpool.h>
#include <util/time.h>
#include <validation.h>
#include <versionbits.h>

#include <boost/multi_index/detail/hash_index_iterator.hpp>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <future>
#include <optional>
#include <stdexcept>
#include <thread>
#include <unordered_set>
#include <utility>

namespace node {

namespace {
constexpr size_t PREFETCH_BATCH_SIZE{128};
constexpr size_t MAX_PREFETCH_INPUTS{MAX_BLOCK_WEIGHT / (41 * WITNESS_SCALE_FACTOR)};
constexpr size_t MAX_PREFETCH_MEMORY{8_MiB};
constexpr unsigned MAX_PREFETCH_COLLECTIONS{8};
std::atomic<unsigned> g_prefetch_collections{0};

/** Limit both retained storage and worker count across all collections. */
struct PrefetchPermit {
    bool acquired{false};
    PrefetchPermit()
    {
        unsigned count{g_prefetch_collections.load()};
        while (count < MAX_PREFETCH_COLLECTIONS) {
            if (g_prefetch_collections.compare_exchange_weak(count, count + 1)) {
                acquired = true;
                break;
            }
        }
    }
    ~PrefetchPermit()
    {
        if (acquired) --g_prefetch_collections;
    }
};
} // namespace

struct TxCollection::Prefetch {
    static std::vector<COutPoint> MakeQueue()
    {
        std::vector<COutPoint> inputs;
        inputs.reserve(MAX_PREFETCH_INPUTS);
        return inputs;
    }
    std::unique_ptr<PrefetchPermit> m_permit;
    ChainstateManager& m_chainman;
    const util::SignalInterrupt& m_interrupt;
    Mutex m_mutex;
    std::condition_variable m_cv;
    std::atomic<bool> m_stop{false};
    std::vector<COutPoint> m_inputs GUARDED_BY(m_mutex);
    size_t m_next GUARDED_BY(m_mutex){0};
    bool m_busy GUARDED_BY(m_mutex){false};
    const Chainstate* m_chainstate GUARDED_BY(m_mutex){nullptr};
    const CBlockIndex* m_tip GUARDED_BY(m_mutex){nullptr};
    const CCoinsViewCache* m_base GUARDED_BY(m_mutex){nullptr};
    CoinsViewPrefetch m_view;
    std::thread m_thread;

    Prefetch(ChainstateManager& chainman, std::unique_ptr<PrefetchPermit> permit)
        : m_permit{std::move(permit)}, m_chainman{chainman}, m_interrupt{chainman.m_interrupt}, m_inputs{MakeQueue()}, m_view{&CoinsViewEmpty::Get(), MAX_PREFETCH_MEMORY - memusage::DynamicUsage(m_inputs), MAX_PREFETCH_INPUTS}
    {
    }

    static std::unique_ptr<Prefetch> Create(ChainstateManager& chainman)
    {
        auto permit{std::make_unique<PrefetchPermit>()};
        if (!permit->acquired) return nullptr;
        return std::make_unique<Prefetch>(chainman, std::move(permit));
    }

    ~Prefetch()
    {
        Stop();
        if (m_thread.joinable()) {
            AssertLockNotHeld(cs_main);
            m_thread.join();
        }
    }

    void Stop() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        {
            LOCK(m_mutex);
            m_stop = true;
        }
        m_cv.notify_all();
    }

    void Add(const std::vector<COutPoint>& inputs) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        {
            LOCK(m_mutex);
            if (m_stop) return;
            const size_t count{std::min(inputs.size(), MAX_PREFETCH_INPUTS - m_inputs.size())};
            m_inputs.insert(m_inputs.end(), inputs.begin(), inputs.begin() + count);
        }
        if (!m_thread.joinable()) {
            m_thread = std::thread(&util::TraceThread, "txprefetch", [this]() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) { Run(); });
        }
        m_cv.notify_all();
    }

    size_t Room() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_stop ? 0 : MAX_PREFETCH_INPUTS - m_inputs.size();
    }

    /** The caller excludes both chain changes and active validation readers. */
    void Bind(Chainstate& chainstate) EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_mutex)
    {
        LOCK(m_mutex);
        auto& base{chainstate.CoinsTip()};
        if (m_chainstate != &chainstate || m_tip != chainstate.m_chain.Tip() || m_base != &base) {
            m_view.Reset(base);
            m_chainstate = &chainstate;
            m_tip = chainstate.m_chain.Tip();
            m_base = &base;
        }
    }

    void Run() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        while (true) {
            std::vector<COutPoint> batch;
            {
                WAIT_LOCK(m_mutex, lock);
                m_cv.wait(lock, [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) { return m_stop || m_next < m_inputs.size(); });
                if (m_stop || m_interrupt) {
                    m_stop = true;
                    break;
                }
                const size_t count{std::min(PREFETCH_BATCH_SIZE, m_inputs.size() - m_next)};
                batch.assign(m_inputs.begin() + m_next, m_inputs.begin() + m_next + count);
                m_next += count;
                m_busy = true;
            }
            while (!m_stop) {
                if (m_interrupt) {
                    Stop();
                    break;
                }
                {
                    // A cancellable wait avoids leaving a worker blocked on
                    // cs_main after MakeTemplate hands its work to validation.
                    TRY_LOCK(cs_main, main_lock);
                    if (main_lock) {
                        if (m_stop) break;
                        // Shutdown may have reset the coin views while this
                        // worker was waiting for cs_main. Check the interrupt
                        // before touching the chainstate manager or its views.
                        if (m_interrupt) {
                            Stop();
                            break;
                        }
                        auto& chainstate{m_chainman.ActiveChainstate()};
                        if (!chainstate.CanFlushToDisk()) {
                            Stop();
                            break;
                        }
                        Bind(chainstate);
                        std::atomic<size_t> next{0};
                        auto fetch = [&] {
                            while (!m_stop && !m_interrupt) {
                                const auto index{next.fetch_add(1, std::memory_order_relaxed)};
                                if (index >= batch.size()) break;
                                if (!m_view.PrefetchCoin(batch[index])) {
                                    Stop(); // Do not read coins that cannot be retained.
                                    break;
                                }
                            }
                        };
                        // Keep the base view stable until every reader finishes.
                        // Pool tasks only read coins; they never acquire cs_main.
                        auto& pool{*chainstate.ConnectBlockView().GetThreadPool()};
                        const auto workers{std::min(pool.WorkersCount(), batch.size())};
                        if (workers == 0) {
                            Stop();
                            break;
                        }
                        std::vector<std::function<void()>> tasks(workers, fetch);
                        if (auto futures{pool.Submit(std::move(tasks))}) {
                            // Drain all readers before propagating any exception.
                            for (auto& future : *futures) future.wait();
                            for (auto& future : *futures) future.get();
                        } else {
                            Stop(); // Validation can fetch the remaining coins.
                        }
                        break;
                    }
                }
                WAIT_LOCK(m_mutex, lock);
                m_cv.wait_for(lock, std::chrono::milliseconds{1}, [this] { return m_stop.load(); });
            }
            {
                LOCK(m_mutex);
                m_busy = false;
            }
            m_cv.notify_all();
        }
        {
            LOCK(m_mutex);
            m_busy = false;
        }
        m_cv.notify_all();
    }

    void Wait() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        AssertLockNotHeld(cs_main);
        WAIT_LOCK(m_mutex, lock);
        m_cv.wait(lock, [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) { return m_stop || (!m_busy && m_next == m_inputs.size()); });
    }

    PrefetchInfo Info() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return {m_view.GetCacheSize(), memusage::DynamicUsage(m_inputs) + m_view.DynamicMemoryUsage()};
    }
};

TxCollection::TxCollection(std::vector<Wtxid> wtxids, ChainstateManager& chainman, CTxMemPool& mempool)
    : m_wtxids(std::move(wtxids)),
      m_chainman(chainman),
      m_mempool(mempool)
{
    // Check for excessively high numbers of transactions.
    if (m_wtxids.size() > MAX_BLOCK_WEIGHT / MIN_TRANSACTION_WEIGHT) {
        throw std::runtime_error(strprintf("too many wtxids (%d > %d)", m_wtxids.size(), MAX_BLOCK_WEIGHT / MIN_TRANSACTION_WEIGHT));
    }
    m_transactions.reserve(m_wtxids.size());
    for (const auto& wtxid : m_wtxids) {
        if (!m_transactions.emplace(wtxid, nullptr).second) {
            throw std::runtime_error(strprintf("duplicate wtxid %s", wtxid.ToString()));
        }
    }
    {
        LOCK(m_mutex);
        std::vector<CTransactionRef> found;
        {
            LOCK(m_mempool.cs);
            for (auto& [wtxid, tx] : m_transactions) {
                if (const auto it{m_mempool.GetIter(wtxid)}) {
                    tx = (*it)->GetSharedTx();
                    found.push_back(tx);
                }
            }
        }
        // A complete collection has no missing-transaction round-trip to
        // overlap. Let validation fetch its inputs without speculative setup.
        if (found.size() != m_transactions.size()) QueuePrefetch(found);
    }
}

TxCollection::~TxCollection() = default;

void TxCollection::QueuePrefetch(const std::vector<CTransactionRef>& txs)
{
    AssertLockHeld(m_mutex);
    if (txs.empty()) return;
    if (!m_prefetch) m_prefetch = Prefetch::Create(m_chainman);
    if (!m_prefetch) return;
    const size_t room{m_prefetch->Room()};
    if (!room) return;

    std::unordered_set<Txid, SaltedTxidHasher> collected;
    for (const auto& [_, tx] : m_transactions) {
        if (tx) collected.insert(tx->GetHash());
    }
    std::vector<COutPoint> inputs;
    for (const auto& tx : txs) {
        for (const auto& txin : tx->vin) {
            if (inputs.size() == room) break;
            if (!collected.contains(txin.prevout.hash)) inputs.push_back(txin.prevout);
        }
        if (inputs.size() == room) break;
    }
    m_prefetch->Add(inputs);
}

void TxCollection::WaitForPrefetch()
{
    Prefetch* prefetch{WITH_LOCK(m_mutex, return m_prefetch.get())};
    if (prefetch) prefetch->Wait();
}

TxCollection::PrefetchInfo TxCollection::GetPrefetchInfo() const
{
    LOCK(m_mutex);
    return m_prefetch ? m_prefetch->Info() : PrefetchInfo{};
}

std::vector<uint32_t> TxCollection::UnknownTxPos() const
{
    LOCK(m_mutex);
    std::vector<uint32_t> result;
    for (size_t i{0}; i < m_wtxids.size(); ++i) {
        // Every requested wtxid is a key (added in the constructor), so at()
        // is safe; a null value means the transaction is still missing.
        if (!m_transactions.at(m_wtxids[i])) result.push_back(static_cast<uint32_t>(i));
    }
    return result;
}

void TxCollection::AddMissingTxs(const std::vector<CTransactionRef>& txs)
{
    LOCK(m_mutex);
    // Reject a list with more transactions than the whole collection.
    // Ideally the IPC layer would enforce a limit based on the maximum block
    // size before deserializing the transactions, but it currently cannot.
    if (txs.size() > m_transactions.size()) {
        throw std::runtime_error(strprintf("too many transactions (%d > %d)", txs.size(), m_transactions.size()));
    }
    // Check for null entries and unexpected or duplicate wtxids before adding any
    // transaction, so a failed call leaves the collection unchanged.
    std::unordered_set<Wtxid, SaltedWtxidHasher> seen;
    seen.reserve(txs.size());
    for (const auto& tx : txs) {
        if (!tx) throw std::runtime_error("unexpected null transaction");
        const auto& wtxid{tx->GetWitnessHash()};
        if (!m_transactions.contains(wtxid)) {
            throw std::runtime_error(strprintf("unexpected wtxid %s", wtxid.ToString()));
        }
        if (!seen.insert(wtxid).second) {
            throw std::runtime_error(strprintf("duplicate wtxid %s", wtxid.ToString()));
        }
    }
    std::vector<CTransactionRef> added;
    for (const auto& tx : txs) {
        auto& entry{m_transactions.at(tx->GetWitnessHash())};
        if (!entry) {
            entry = tx;
            added.push_back(tx);
        }
    }
    QueuePrefetch(added);
}

std::unique_ptr<CBlockTemplate> TxCollection::MakeTemplate(const uint256& prevhash,
                                                           const CTransactionRef& coinbase,
                                                           std::string& reason,
                                                           std::string& debug)
{
    reason.clear();
    debug.clear();

    auto block_template{[&]() -> std::unique_ptr<CBlockTemplate> {
        std::vector<CTransactionRef> transactions;
        Prefetch* prefetch{nullptr};
        {
            LOCK(m_mutex);
            if (std::ranges::any_of(m_transactions, [](const auto& entry) { return !entry.second; })) {
                reason = "missing-txs";
                debug = "collected transaction(s) still missing";
                return nullptr;
            }
            transactions.reserve(m_wtxids.size());
            for (const auto& wtxid : m_wtxids) {
                const auto it{m_transactions.find(wtxid)};
                Assert(it != m_transactions.end());
                Assert(it->second);
                transactions.push_back(it->second);
            }
            prefetch = m_prefetch.get();
            if (prefetch) prefetch->Stop();
        }
        ChainstateManager& chainman{m_chainman};
        LOCK(chainman.GetMutex());
        auto& chainstate{chainman.ActiveChainstate()};
        if (prefetch) prefetch->Bind(chainstate);
        const CBlockIndex* current_tip{chainman.ActiveTip()};
        if (!current_tip || prevhash != current_tip->GetBlockHash()) {
            reason = "inconclusive-not-best-prevblk";
            debug = strprintf("requested prevhash %s does not match current tip %s",
                              prevhash.ToString(),
                              current_tip ? current_tip->GetBlockHash().ToString() : "(none)");
            return nullptr;
        }
        const CBlockIndex* const prev_block{Assert(chainman.m_blockman.LookupBlockIndex(prevhash))};
        auto block_template{std::make_unique<CBlockTemplate>()};
        CBlock& block{block_template->block};

        block.hashPrevBlock = prevhash;
        block.nVersion = chainman.m_versionbitscache.ComputeBlockVersion(prev_block, chainman.GetParams().GetConsensus());
        if (chainman.GetParams().MineBlocksOnDemand()) {
            block.nVersion = gArgs.GetIntArg("-blockversion", block.nVersion);
        }
        block.nTime = TicksSinceEpoch<std::chrono::seconds>(NodeClock::now());

        // Placeholder for the coinbase tx, filled in after the collected
        // transactions are added so the witness commitment is current.
        block.vtx.emplace_back();

        for (const auto& tx : transactions) {
            block.vtx.push_back(tx);
        }

        if (coinbase) {
            // Validate the block with the caller-provided coinbase, which is
            // expected to commit to the collected transactions (witness
            // commitment) and the next block height (BIP34).
            block.vtx[0] = coinbase;
        } else {
            // Validate with a node-generated dummy coinbase. Checks involving the
            // coinbase still pass, but say nothing about the coinbase the caller
            // intends to use.
            BlockAssembler{
                chainman.ActiveChainstate(),
                &m_mempool,
                BlockCreateOptions{.use_mempool = false},
            }
                .CreateCoinbaseTx(block, *prev_block, /*fees=*/0);
        }

        UpdateTime(&block, chainman.GetParams().GetConsensus(), prev_block);
        block.nBits = GetNextWorkRequired(prev_block, &block, chainman.GetParams().GetConsensus());
        block.nNonce = 0;

        // Even collections without a prefetch permit use non-caching fallback
        // reads. Each TestBlockValidity call adds its own mutable validation cache.
        CoinsViewPrefetch fallback{&chainstate.CoinsTip(), /*max_memory=*/0, /*max_entries=*/0};
        BlockValidationState state{TestBlockValidity(chainstate, block, /*check_pow=*/false, /*check_merkle_root=*/false,
                                                     prefetch ? &prefetch->m_view : &fallback)};
        if (!state.IsValid()) {
            reason = state.GetRejectReason();
            debug = state.GetDebugMessage();
            return nullptr;
        }
        return block_template;
    }()};
    // This follows the SubmitBlock convention: a missing template must set a
    // rejection reason, and a successful one must not.
    CHECK_NONFATAL((block_template != nullptr) == reason.empty());
    return block_template;
}
} // namespace node

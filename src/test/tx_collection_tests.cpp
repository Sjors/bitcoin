// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <arith_uint256.h>
#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <key.h>
#include <node/block_template_manager.h>
#include <node/miner.h>
#include <node/tx_collection.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <sync.h>
#include <test/util/common.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <tinyformat.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/byte_units.h>
#include <util/signalinterrupt.h>
#include <util/threadpool.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {
/** Count disk-facing reads of one input while preserving normal error handling. */
class CountedCoinsView : public CCoinsViewBacked
{
    Chainstate& m_chainstate;
    const COutPoint m_input;

public:
    mutable std::atomic<unsigned> input_reads{0};
    mutable std::atomic<unsigned> caching_reads{0};
    CountedCoinsView(Chainstate& chainstate, const COutPoint& input) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
        : CCoinsViewBacked{&chainstate.CoinsErrorCatcher()}, m_chainstate{chainstate}, m_input{input}
    {
        chainstate.CoinsTip().SetBackend(*this);
    }
    ~CountedCoinsView()
    {
        LOCK(cs_main);
        m_chainstate.CoinsTip().SetBackend(*base);
    }
    std::optional<Coin> GetCoin(const COutPoint& outpoint) const override
    {
        ++caching_reads;
        return base->GetCoin(outpoint);
    }
    std::optional<Coin> PeekCoin(const COutPoint& outpoint) const override
    {
        if (outpoint == m_input) ++input_reads;
        return base->PeekCoin(outpoint);
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(tx_collection_tests, RegTestingSetup)

BOOST_AUTO_TEST_CASE(collection_limits)
{
    auto& manager{*m_node.block_template_manager};
    BOOST_CHECK(manager.CreateTxCollection({}));
    const auto wtxid{Wtxid::FromUint256(uint256{1})};
    BOOST_CHECK_EXCEPTION(manager.CreateTxCollection({wtxid, wtxid}), std::runtime_error,
                          HasReason{"duplicate wtxid " + wtxid.ToString()});

    std::vector<Wtxid> wtxids;
    const auto max_txs{MAX_BLOCK_WEIGHT / MIN_TRANSACTION_WEIGHT};
    for (uint32_t i{0}; i < max_txs; ++i) {
        wtxids.push_back(Wtxid::FromUint256(ArithToUint256(arith_uint256{i})));
    }
    // The maximum succeeds; one more request fails before any mempool lookup.
    BOOST_CHECK(manager.CreateTxCollection(wtxids));
    wtxids.push_back(Wtxid::FromUint256(ArithToUint256(arith_uint256{MAX_BLOCK_WEIGHT})));
    BOOST_CHECK_EXCEPTION(manager.CreateTxCollection(wtxids), std::runtime_error,
                          HasReason{strprintf("too many wtxids (%d > %d)", wtxids.size(), max_txs)});
}

BOOST_AUTO_TEST_CASE(unknown_tx_positions_ignore_mempool_changes)
{
    // The collection retains transactions found in the mempool at creation.
    // Missing entries are filled through addMissingTxs(); the collection is
    // independent of later mempool changes.
    CMutableTransaction tx;
    tx.vin.emplace_back(Txid::FromUint256(uint256{1}), 0);
    tx.vout.emplace_back(1, CScript() << OP_TRUE);
    const auto witness_a{MakeTransactionRef(tx)};
    tx.vin[0].scriptWitness.stack = {{1}};
    const auto witness_b{MakeTransactionRef(tx)};
    // Same txid, different wtxid: only the exact witness variant is present.
    BOOST_CHECK(witness_a->GetHash() == witness_b->GetHash());
    BOOST_CHECK(witness_a->GetWitnessHash() != witness_b->GetWitnessHash());

    auto& pool{*m_node.mempool};
    auto& manager{*m_node.block_template_manager};
    TryAddToMempool(pool, TestMemPoolEntryHelper{}.FromTx(witness_b));
    BOOST_REQUIRE(pool.exists(witness_b->GetWitnessHash()));
    auto collection{manager.CreateTxCollection({witness_a->GetWitnessHash(), witness_b->GetWitnessHash()})};
    BOOST_CHECK(collection->UnknownTxPos() == std::vector<uint32_t>{0});

    // The collection retains witness_b after it leaves the mempool.
    WITH_LOCK(pool.cs, pool.removeRecursive(*witness_b, MemPoolRemovalReason::EXPIRY));
    BOOST_REQUIRE(!pool.exists(witness_b->GetWitnessHash()));
    BOOST_CHECK(collection->UnknownTxPos() == std::vector<uint32_t>{0});

    // Missing entries are only filled through addMissingTxs(), not automatically
    // when transactions enter the mempool. This behavior is not essential.
    TryAddToMempool(pool, TestMemPoolEntryHelper{}.FromTx(witness_a));
    BOOST_REQUIRE(pool.exists(witness_a->GetWitnessHash()));
    BOOST_CHECK(collection->UnknownTxPos() == std::vector<uint32_t>{0});
    BOOST_CHECK(manager.CreateTxCollection({})->UnknownTxPos().empty());
}

BOOST_AUTO_TEST_CASE(add_missing_transactions)
{
    // Use different locktimes to give the transactions distinct txids and wtxids;
    // locktime behavior itself is not being tested.
    CMutableTransaction tx;
    tx.nLockTime = 1;
    const auto tx_a{MakeTransactionRef(tx)};
    const auto wtxid_a{tx_a->GetWitnessHash()};
    tx.nLockTime = 2;
    const auto tx_b{MakeTransactionRef(tx)};
    const auto wtxid_b{tx_b->GetWitnessHash()};
    tx.nLockTime = 3;
    const auto tx_c{MakeTransactionRef(tx)};
    const auto wtxid_c{tx_c->GetWitnessHash()};
    auto collection{m_node.block_template_manager->CreateTxCollection({wtxid_a, wtxid_b})};

    // An empty submission leaves both positions missing.
    collection->AddMissingTxs({});
    BOOST_CHECK((collection->UnknownTxPos() == std::vector<uint32_t>{0, 1}));

    // A rejected batch must also leave the collection unchanged: tx_a must still
    // be missing, even though it is one of the requested transactions.
    BOOST_CHECK_EXCEPTION(collection->AddMissingTxs({tx_a, tx_c}), std::runtime_error,
                          HasReason{"unexpected wtxid " + wtxid_c.ToString()});
    BOOST_CHECK((collection->UnknownTxPos() == std::vector<uint32_t>{0, 1}));
    BOOST_CHECK_EXCEPTION(collection->AddMissingTxs({tx_a, nullptr}), std::runtime_error,
                          HasReason{"unexpected null transaction"});
    BOOST_CHECK((collection->UnknownTxPos() == std::vector<uint32_t>{0, 1}));
    BOOST_CHECK_EXCEPTION(collection->AddMissingTxs({tx_a, tx_a}), std::runtime_error,
                          HasReason{"duplicate wtxid " + wtxid_a.ToString()});
    BOOST_CHECK((collection->UnknownTxPos() == std::vector<uint32_t>{0, 1}));
    BOOST_CHECK_EXCEPTION(collection->AddMissingTxs({tx_a, tx_a, tx_a}), std::runtime_error,
                          HasReason{"too many transactions (3 > 2)"});
    BOOST_CHECK((collection->UnknownTxPos() == std::vector<uint32_t>{0, 1}));

    // Submitting tx_b fills position 1, leaving only position 0 missing.
    collection->AddMissingTxs({tx_b});
    BOOST_CHECK(collection->UnknownTxPos() == std::vector<uint32_t>{0});
    // Add tx_a at position 0 while resubmitting tx_b, which is already at position 1.
    collection->AddMissingTxs({tx_a, tx_b});
    BOOST_CHECK(collection->UnknownTxPos().empty());
}

struct TxCollectionTemplateSetup : RegTestingSetup {
    const uint256 m_tip{WITH_LOCK(m_node.chainman->GetMutex(), return m_node.chainman->ActiveTip()->GetBlockHash())};
    const std::unique_ptr<node::TxCollection> m_collection{m_node.block_template_manager->CreateTxCollection({})};
};

BOOST_FIXTURE_TEST_CASE(template_preconditions, TxCollectionTemplateSetup)
{
    // Reuse the outputs across failure and success to check that errors clear.
    std::string reason{"old reason"};
    std::string debug{"old debug"};
    BOOST_CHECK(!m_collection->MakeTemplate(uint256{1}, {}, reason, debug));
    BOOST_CHECK_EQUAL(reason, "inconclusive-not-best-prevblk");
    BOOST_CHECK(!debug.empty());
    auto block_template{m_collection->MakeTemplate(m_tip, {}, reason, debug)};
    BOOST_REQUIRE(block_template);
    BOOST_CHECK(reason.empty());
    BOOST_CHECK(debug.empty());
    BOOST_CHECK(block_template->block.hashPrevBlock == m_tip);
    BOOST_REQUIRE_EQUAL(block_template->block.vtx.size(), 1);
    BOOST_CHECK(block_template->block.vtx[0]->IsCoinBase());
}

BOOST_FIXTURE_TEST_CASE(template_transactions, TestChain100Setup)
{
    // A valid parent and child make transaction order observable in validation.
    const auto parent{CreateValidMempoolTransaction(m_coinbase_txns[0], 0, 1, coinbaseKey,
                                                    CScript() << OP_TRUE, 49 * COIN, /*submit=*/false)};
    CMutableTransaction child;
    child.vin.emplace_back(parent.GetHash(), 0);
    child.vout.emplace_back(48 * COIN, CScript() << OP_TRUE);
    const auto parent_ref{MakeTransactionRef(parent)}, child_ref{MakeTransactionRef(child)};
    auto& manager{*m_node.block_template_manager};
    auto& chainman{*m_node.chainman};
    const auto tip{WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()->GetBlockHash())};
    auto collection{manager.CreateTxCollection({parent_ref->GetWitnessHash(), child_ref->GetWitnessHash()})};
    std::string reason;
    std::string debug;
    BOOST_CHECK(!collection->MakeTemplate(tip, {}, reason, debug));
    BOOST_CHECK_EQUAL(reason, "missing-txs");
    BOOST_CHECK(!debug.empty());

    collection->AddMissingTxs({parent_ref, child_ref});
    auto block_template{collection->MakeTemplate(tip, {}, reason, debug)};
    BOOST_REQUIRE(block_template);
    BOOST_REQUIRE_EQUAL(block_template->block.vtx.size(), 3);
    BOOST_CHECK(block_template->block.vtx[1] == parent_ref);
    BOOST_CHECK(block_template->block.vtx[2] == child_ref);

    auto reversed{manager.CreateTxCollection({child_ref->GetWitnessHash(), parent_ref->GetWitnessHash()})};
    reversed->AddMissingTxs({parent_ref, child_ref});
    BOOST_CHECK(!reversed->MakeTemplate(tip, {}, reason, debug));
    BOOST_CHECK_EQUAL(reason, "bad-txns-inputs-missingorspent");

    const auto mined{CreateAndProcessBlock({parent, child}, CScript() << OP_TRUE)};
    const auto new_tip{WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()->GetBlockHash())};
    BOOST_REQUIRE(new_tip == mined.GetHash());
    BOOST_CHECK(!collection->MakeTemplate(tip, {}, reason, debug));
    BOOST_CHECK_EQUAL(reason, "inconclusive-not-best-prevblk");
    BOOST_CHECK(!collection->MakeTemplate(new_tip, {}, reason, debug));
    BOOST_CHECK_EQUAL(reason, "bad-txns-BIP30");
}

BOOST_FIXTURE_TEST_CASE(supplied_coinbase, TxCollectionTemplateSetup)
{
    // Start with a valid coinbase, then break its amount and witness commitment.
    std::string reason;
    std::string debug;
    auto original{m_collection->MakeTemplate(m_tip, {}, reason, debug)};
    BOOST_REQUIRE(original);
    const auto coinbase{original->block.vtx[0]};
    auto supplied{m_collection->MakeTemplate(m_tip, coinbase, reason, debug)};
    BOOST_REQUIRE(supplied);
    BOOST_CHECK(supplied->block.vtx[0] == coinbase);

    CMutableTransaction overpaying{*coinbase};
    ++overpaying.vout[0].nValue;
    BOOST_CHECK(!m_collection->MakeTemplate(m_tip, MakeTransactionRef(overpaying), reason, debug));
    BOOST_CHECK_EQUAL(reason, "bad-cb-amount");

    CMutableTransaction bad_commitment{*coinbase};
    const int commitment_index{GetWitnessCommitmentIndex(original->block)};
    BOOST_REQUIRE(commitment_index >= 0);
    bad_commitment.vout[commitment_index].scriptPubKey[6] ^= 1;
    BOOST_CHECK(!m_collection->MakeTemplate(m_tip, MakeTransactionRef(bad_commitment), reason, debug));
    BOOST_CHECK_EQUAL(reason, "bad-witness-merkle-match");
}

BOOST_FIXTURE_TEST_CASE(complete_collection_skips_speculative_prefetch, TestChain100Setup)
{
    const auto tx{MakeTransactionRef(CreateValidMempoolTransaction(m_coinbase_txns[0], 0, 1, coinbaseKey,
                                                                   CScript() << OP_TRUE, 49 * COIN, false))};
    auto& chainstate{m_node.chainman->ActiveChainstate()};
    chainstate.ForceFlushStateToDisk();
    TryAddToMempool(*m_node.mempool, TestMemPoolEntryHelper{}.Fee(COIN).FromTx(tx));
    auto counted{WITH_LOCK(cs_main, return std::make_unique<CountedCoinsView>(chainstate, tx->vin[0].prevout))};
    auto collection{m_node.block_template_manager->CreateTxCollection({tx->GetWitnessHash()})};
    BOOST_CHECK(collection->UnknownTxPos().empty());
    collection->WaitForPrefetch();
    BOOST_CHECK_EQUAL(collection->GetPrefetchInfo().memory_usage, 0);
    BOOST_CHECK_EQUAL(counted->input_reads.load(), 0);
    const auto tip{WITH_LOCK(cs_main, return chainstate.m_chain.Tip()->GetBlockHash())};
    std::string reason, debug;
    BOOST_REQUIRE(collection->MakeTemplate(tip, {}, reason, debug));
    BOOST_CHECK_EQUAL(counted->input_reads.load(), 1);
    BOOST_CHECK_EQUAL(counted->caching_reads.load(), 0);
    BOOST_CHECK_EQUAL(collection->GetPrefetchInfo().memory_usage, 0);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return chainstate.CoinsTip().GetCacheSize()), 0);
}

BOOST_FIXTURE_TEST_CASE(prefetched_inputs_are_reused_without_cache_growth, TestChain100Setup)
{
    mineBlocks(1); // Mature both coinbase inputs.
    const auto tx{MakeTransactionRef(CreateValidMempoolTransaction(m_coinbase_txns[0], 0, 1, coinbaseKey,
                                                                   CScript() << OP_TRUE, 49 * COIN, false))};
    const auto missing{MakeTransactionRef(CreateValidMempoolTransaction(m_coinbase_txns[1], 0, 2, coinbaseKey,
                                                                        CScript() << OP_TRUE, 49 * COIN, false))};
    auto& chainstate{m_node.chainman->ActiveChainstate()};
    chainstate.ForceFlushStateToDisk();
    TryAddToMempool(*m_node.mempool, TestMemPoolEntryHelper{}.Fee(COIN).FromTx(tx));
    auto counted{WITH_LOCK(cs_main, return std::make_unique<CountedCoinsView>(chainstate, tx->vin[0].prevout))};
    auto collection{m_node.block_template_manager->CreateTxCollection({tx->GetWitnessHash(), missing->GetWitnessHash()})};
    collection->WaitForPrefetch();
    BOOST_CHECK_EQUAL(collection->GetPrefetchInfo().coins, 1);
    BOOST_CHECK_EQUAL(counted->input_reads.load(), 1);
    collection->AddMissingTxs({missing});
    const auto tip{WITH_LOCK(cs_main, return chainstate.m_chain.Tip()->GetBlockHash())};
    std::string reason, debug;
    for (unsigned i{0}; i < 3; ++i) {
        BOOST_REQUIRE(collection->MakeTemplate(tip, {}, reason, debug));
        BOOST_CHECK_EQUAL(counted->input_reads.load(), 1);
        BOOST_CHECK_EQUAL(counted->caching_reads.load(), 0);
        BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return chainstate.CoinsTip().GetCacheSize()), 0);
    }
}

BOOST_FIXTURE_TEST_CASE(prefetched_inputs_are_invalidated_on_tip_change, TestChain100Setup)
{
    const auto tx{MakeTransactionRef(CreateValidMempoolTransaction(m_coinbase_txns[0], 0, 1, coinbaseKey,
                                                                   CScript() << OP_TRUE, 49 * COIN, false))};
    auto collection{m_node.block_template_manager->CreateTxCollection({tx->GetWitnessHash()})};
    collection->AddMissingTxs({tx});
    collection->WaitForPrefetch();
    BOOST_CHECK_EQUAL(collection->GetPrefetchInfo().coins, 1);
    const auto conflicting{CreateValidMempoolTransaction(m_coinbase_txns[0], 0, 1, coinbaseKey,
                                                         CScript() << OP_TRUE, 48 * COIN, false)};
    CreateAndProcessBlock({conflicting}, CScript() << OP_TRUE);
    const auto tip{WITH_LOCK(cs_main, return m_node.chainman->ActiveTip()->GetBlockHash())};
    std::string reason, debug;
    BOOST_CHECK(!collection->MakeTemplate(tip, {}, reason, debug));
    BOOST_CHECK_EQUAL(reason, "bad-txns-inputs-missingorspent");
}

BOOST_AUTO_TEST_CASE(prefetch_is_bounded_across_collections)
{
    CMutableTransaction tx;
    tx.vin.emplace_back(Txid::FromUint256(uint256{1}), 0);
    tx.vout.emplace_back(1, CScript() << OP_TRUE);
    const auto ref{MakeTransactionRef(tx)};
    std::vector<std::unique_ptr<node::TxCollection>> collections;
    unsigned enabled{0};
    size_t usage{0};
    for (unsigned i{0}; i < 9; ++i) {
        auto collection{m_node.block_template_manager->CreateTxCollection({ref->GetWitnessHash()})};
        collection->AddMissingTxs({ref});
        collection->WaitForPrefetch();
        const auto info{collection->GetPrefetchInfo()};
        enabled += info.memory_usage > 0;
        usage += info.memory_usage;
        BOOST_CHECK(info.memory_usage <= 8_MiB);
        collections.push_back(std::move(collection));
    }
    BOOST_CHECK_EQUAL(enabled, 8);
    BOOST_CHECK(usage <= 64_MiB);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveChainstate().CoinsTip().GetCacheSize()), 0);
}

BOOST_FIXTURE_TEST_CASE(prefetch_reads_inputs_in_parallel, TestChain100Setup)
{
    class ConcurrentCoinsView : public CountedCoinsView
    {
        mutable Mutex m_mutex;
        mutable std::condition_variable m_cv;
        mutable unsigned m_started GUARDED_BY(m_mutex){0};

    public:
        using CountedCoinsView::CountedCoinsView;
        mutable std::atomic<bool> overlapped{true};
        std::optional<Coin> PeekCoin(const COutPoint& outpoint) const override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
        {
            {
                WAIT_LOCK(m_mutex, lock);
                ++m_started;
                m_cv.notify_all();
                // A timeout lets a serial implementation fail without hanging.
                if (!m_cv.wait_for(lock, std::chrono::seconds{5}, [&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) { return m_started >= 2; })) {
                    overlapped = false;
                }
            }
            return CountedCoinsView::PeekCoin(outpoint);
        }
    };
    auto& chainstate{m_node.chainman->ActiveChainstate()};
    chainstate.ForceFlushStateToDisk();
    CMutableTransaction tx;
    tx.vin.emplace_back(m_coinbase_txns[0]->GetHash(), 0);
    tx.vin.emplace_back(m_coinbase_txns[1]->GetHash(), 0);
    tx.vout.emplace_back(1, CScript() << OP_TRUE);
    const auto ref{MakeTransactionRef(tx)};
    auto counted{WITH_LOCK(cs_main, return std::make_unique<ConcurrentCoinsView>(chainstate, tx.vin[0].prevout))};
    auto collection{m_node.block_template_manager->CreateTxCollection({ref->GetWitnessHash()})};
    collection->AddMissingTxs({ref});
    collection->WaitForPrefetch();
    BOOST_CHECK(counted->overlapped.load());
    BOOST_CHECK_EQUAL(collection->GetPrefetchInfo().coins, 2);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return chainstate.CoinsTip().GetCacheSize()), 0);
}

BOOST_FIXTURE_TEST_CASE(prefetch_respects_fetch_pool_availability, TestChain100Setup)
{
    auto& chainstate{m_node.chainman->ActiveChainstate()};
    chainstate.ForceFlushStateToDisk();
    const auto pool{WITH_LOCK(cs_main, return chainstate.ConnectBlockView().GetThreadPool())};
    CMutableTransaction tx;
    tx.vin.emplace_back(m_coinbase_txns[0]->GetHash(), 0);
    tx.vin.emplace_back(m_coinbase_txns[1]->GetHash(), 0);
    tx.vout.emplace_back(1, CScript() << OP_TRUE);
    const auto ref{MakeTransactionRef(tx)};
    for (const int workers : {0, 1, 2}) {
        pool->Stop();
        if (workers) pool->Start(workers);
        // Keep workers registered, but reject submission of new tasks.
        if (workers == 2) pool->Interrupt();
        auto counted{WITH_LOCK(cs_main, return std::make_unique<CountedCoinsView>(chainstate, tx.vin[0].prevout))};
        auto collection{m_node.block_template_manager->CreateTxCollection({ref->GetWitnessHash()})};
        collection->AddMissingTxs({ref});
        collection->WaitForPrefetch();
        BOOST_CHECK_EQUAL(collection->GetPrefetchInfo().coins, workers == 1 ? 2 : 0);
        BOOST_CHECK_EQUAL(counted->input_reads.load(), workers == 1 ? 1 : 0);
        BOOST_CHECK_EQUAL(counted->caching_reads.load(), 0);
        BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return chainstate.CoinsTip().GetCacheSize()), 0);
    }
}

BOOST_AUTO_TEST_CASE(prefetch_memory_limit_does_not_fill_coins_tip)
{
    auto& chainstate{m_node.chainman->ActiveChainstate()};
    CMutableTransaction tx;
    CScript script;
    script.resize(10'000);
    std::fill(script.begin(), script.end(), OP_TRUE);
    {
        LOCK(cs_main);
        for (unsigned i{0}; i < 1000; ++i) {
            const COutPoint input{Txid::FromUint256(ArithToUint256(arith_uint256{i + 1000})), 0};
            tx.vin.emplace_back(input);
            chainstate.CoinsTip().AddCoin(input, Coin{CTxOut{1, script}, 1, false}, false);
        }
    }
    tx.vout.emplace_back(1, CScript() << OP_TRUE);
    chainstate.ForceFlushStateToDisk();
    const auto ref{MakeTransactionRef(tx)};
    auto collection{m_node.block_template_manager->CreateTxCollection({ref->GetWitnessHash()})};
    collection->AddMissingTxs({ref});
    collection->WaitForPrefetch();
    const auto info{collection->GetPrefetchInfo()};
    BOOST_CHECK(info.coins > 0);
    BOOST_CHECK(info.coins < 1000);
    BOOST_CHECK(info.memory_usage <= 8_MiB);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return chainstate.CoinsTip().GetCacheSize()), 0);
}

BOOST_FIXTURE_TEST_CASE(validation_cancels_prefetch_waiting_for_cs_main, TestChain100Setup)
{
    const auto tx{MakeTransactionRef(CreateValidMempoolTransaction(m_coinbase_txns[0], 0, 1, coinbaseKey,
                                                                   CScript() << OP_TRUE, 49 * COIN, false))};
    auto& chainstate{m_node.chainman->ActiveChainstate()};
    chainstate.ForceFlushStateToDisk();
    auto counted{WITH_LOCK(cs_main, return std::make_unique<CountedCoinsView>(chainstate, tx->vin[0].prevout))};
    std::unique_ptr<node::TxCollection> collection;
    {
        LOCK(cs_main);
        collection = m_node.block_template_manager->CreateTxCollection({tx->GetWitnessHash()});
        collection->AddMissingTxs({tx});
        const auto tip{chainstate.m_chain.Tip()->GetBlockHash()};
        std::string reason, debug;
        for (unsigned i{0}; i < 3; ++i) {
            BOOST_REQUIRE(collection->MakeTemplate(tip, {}, reason, debug));
            BOOST_CHECK_EQUAL(counted->input_reads.load(), 1);
            BOOST_CHECK_EQUAL(chainstate.CoinsTip().GetCacheSize(), 0);
        }
    }
    collection.reset(); // Joins only after releasing cs_main.
    BOOST_CHECK_EQUAL(counted->input_reads.load(), 1);
}

BOOST_AUTO_TEST_CASE(prefetch_stops_when_shutdown_resets_coin_views)
{
    CMutableTransaction tx;
    tx.vin.emplace_back(Txid::FromUint256(uint256{1}), 0);
    tx.vout.emplace_back(1, CScript() << OP_TRUE);
    const auto ref{MakeTransactionRef(tx)};
    std::unique_ptr<node::TxCollection> collection;
    {
        LOCK(cs_main);
        collection = m_node.block_template_manager->CreateTxCollection({ref->GetWitnessHash()});
        collection->AddMissingTxs({ref});
        BOOST_REQUIRE(m_interrupt());
        // Shutdown resets these views before disconnecting IPC clients. The
        // worker is queued behind cs_main and must not access the absent view.
        m_node.chainman->ActiveChainstate().ResetCoinsViews();
    }
    collection->WaitForPrefetch();
    BOOST_CHECK_EQUAL(collection->GetPrefetchInfo().coins, 0);
}

BOOST_FIXTURE_TEST_CASE(prefetch_budget_exhaustion_preserves_validation, TestChain100Setup)
{
    const auto tx{MakeTransactionRef(CreateValidMempoolTransaction(m_coinbase_txns[0], 0, 1, coinbaseKey,
                                                                   CScript() << OP_TRUE, 49 * COIN, false))};
    auto& chainstate{m_node.chainman->ActiveChainstate()};
    chainstate.ForceFlushStateToDisk();
    auto counted{WITH_LOCK(cs_main, return std::make_unique<CountedCoinsView>(chainstate, tx->vin[0].prevout))};
    std::vector<std::unique_ptr<node::TxCollection>> holders;
    for (unsigned i{0}; i < 8; ++i) {
        auto holder{m_node.block_template_manager->CreateTxCollection({tx->GetWitnessHash()})};
        holder->AddMissingTxs({tx});
        holder->WaitForPrefetch();
        holders.push_back(std::move(holder));
    }
    auto collection{m_node.block_template_manager->CreateTxCollection({tx->GetWitnessHash()})};
    collection->AddMissingTxs({tx});
    BOOST_CHECK_EQUAL(collection->GetPrefetchInfo().memory_usage, 0);
    const auto tip{WITH_LOCK(cs_main, return chainstate.m_chain.Tip()->GetBlockHash())};
    std::string reason, debug;
    BOOST_REQUIRE(collection->MakeTemplate(tip, {}, reason, debug));
    BOOST_CHECK_EQUAL(counted->input_reads.load(), 9);
    BOOST_CHECK_EQUAL(counted->caching_reads.load(), 0);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return chainstate.CoinsTip().GetCacheSize()), 0);
}

BOOST_AUTO_TEST_CASE(prefetch_queue_limits_oversized_collections)
{
    CMutableTransaction tx;
    for (unsigned i{0}; i < 100'000; ++i) {
        tx.vin.emplace_back(Txid::FromUint256(ArithToUint256(arith_uint256{i + 1})), 0);
    }
    tx.vout.emplace_back(1, CScript() << OP_TRUE);
    const auto ref{MakeTransactionRef(tx)};
    auto collection{m_node.block_template_manager->CreateTxCollection({ref->GetWitnessHash()})};
    collection->AddMissingTxs({ref});
    collection->WaitForPrefetch();
    const auto info{collection->GetPrefetchInfo()};
    BOOST_CHECK(info.coins > 0);
    BOOST_CHECK(info.coins <= MAX_BLOCK_WEIGHT / (41 * WITNESS_SCALE_FACTOR));
    BOOST_CHECK(info.memory_usage <= 8_MiB);
}

BOOST_AUTO_TEST_SUITE_END()

// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <bench/bench.h>
#include <coins.h>
#include <consensus/amount.h>
#include <key.h>
#include <node/miner.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/script.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/check.h>
#include <validation.h>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace {

//! Number of transactions in the collection, and inputs per transaction. The
//! resulting template spends NUM_TXS * INPUTS_PER_TX coins from the UTXO set.
constexpr size_t NUM_TXS{1000};
constexpr size_t INPUTS_PER_TX{2};

/** Common state for the TxCollection benchmarks: a chain whose UTXO set
 *  contains NUM_TXS * INPUTS_PER_TX confirmed and flushed-to-disk coins, and
 *  a set of valid transactions spending them. */
struct CollectionSetup {
    std::unique_ptr<TestChain100Setup> test_setup{MakeNoLogFileContext<TestChain100Setup>()};
    std::vector<CTransactionRef> txs;
    std::vector<Wtxid> wtxids;
    std::vector<COutPoint> prevouts;
    uint256 tip;

    CollectionSetup()
    {
        Chainstate& chainstate{test_setup->m_node.chainman->ActiveChainstate()};
        const CKey key{GenerateRandomKey()};
        const CTxOut txout{COIN / 100, GetScriptForDestination(WitnessV1Taproot{XOnlyPubKey(key.GetPubKey())})};
        const std::vector<CKey> keys{test_setup->coinbaseKey, key};

        // Confirm a transaction creating all the coins the collected
        // transactions will spend, then flush them to disk so MakeTemplate()
        // with a cold cache has to read them back.
        auto& coinbase_to_spend{test_setup->m_coinbase_txns[0]};
        const auto [funding_tx, _]{test_setup->CreateValidTransaction(
            {coinbase_to_spend},
            {COutPoint(coinbase_to_spend->GetHash(), 0)},
            chainstate.m_chain.Height() + 1, keys,
            std::vector<CTxOut>(NUM_TXS * INPUTS_PER_TX, txout), {}, {})};
        test_setup->CreateAndProcessBlock({funding_tx}, txout.scriptPubKey);

        const CTransactionRef funding_ref{MakeTransactionRef(funding_tx)};
        for (size_t i{0}; i < NUM_TXS; ++i) {
            std::vector<COutPoint> inputs;
            for (size_t j{0}; j < INPUTS_PER_TX; ++j) {
                inputs.emplace_back(funding_ref->GetHash(), i * INPUTS_PER_TX + j);
            }
            const auto [tx, _fee]{test_setup->CreateValidTransaction(
                {funding_ref}, inputs, chainstate.m_chain.Height(), {key},
                {txout}, {}, {})};
            txs.push_back(MakeTransactionRef(tx));
            wtxids.push_back(txs.back()->GetWitnessHash());
            prevouts.insert(prevouts.end(), inputs.begin(), inputs.end());
        }

        chainstate.ForceFlushStateToDisk();
        tip = WITH_LOCK(cs_main, return chainstate.m_chain.Tip()->GetBlockHash());
    }

    //! Evict the collected transactions' input coins from the coins cache, so
    //! the next MakeTemplate() has to read them from the coins database.
    void UncacheInputs()
    {
        LOCK(cs_main);
        CCoinsViewCache& coins{test_setup->m_node.chainman->ActiveChainstate().CoinsTip()};
        for (const auto& outpoint : prevouts) coins.Uncache(outpoint);
    }
};

//! Template creation when every input coin has to be read from disk.
void TxCollectionTemplateColdCoins(benchmark::Bench& bench)
{
    CollectionSetup setup;
    node::TxCollection collection{setup.wtxids, setup.test_setup->m_node};
    collection.AddMissingTxs(setup.txs);
    collection.WaitForPrefetch();

    std::string reason, debug;
    bench.unit("template").run([&] {
        setup.UncacheInputs();
        const auto block_template{collection.MakeTemplate(setup.tip, /*coinbase=*/nullptr, reason, debug)};
        assert(block_template);
    });
}

//! Template creation after the background prefetch has warmed the coins
//! cache. The difference with TxCollectionTemplateColdCoins is the latency
//! that prefetching removes from the critical path.
void TxCollectionTemplatePrefetchedCoins(benchmark::Bench& bench)
{
    CollectionSetup setup;
    node::TxCollection collection{setup.wtxids, setup.test_setup->m_node};
    collection.AddMissingTxs(setup.txs);
    collection.WaitForPrefetch();

    std::string reason, debug;
    bench.unit("template").run([&] {
        const auto block_template{collection.MakeTemplate(setup.tip, /*coinbase=*/nullptr, reason, debug)};
        assert(block_template);
    });
}

//! The prefetch itself: collect the transactions and wait for their input
//! coins to be cached. In real usage this overlaps with the client's request
//! for missing transactions, so it does not add to template latency.
void TxCollectionPrefetch(benchmark::Bench& bench)
{
    CollectionSetup setup;

    bench.unit("collection").run([&] {
        setup.UncacheInputs();
        node::TxCollection collection{setup.wtxids, setup.test_setup->m_node};
        collection.AddMissingTxs(setup.txs);
        collection.WaitForPrefetch();
    });
}

} // namespace

BENCHMARK(TxCollectionTemplateColdCoins);
BENCHMARK(TxCollectionTemplatePrefetchedCoins);
BENCHMARK(TxCollectionPrefetch);

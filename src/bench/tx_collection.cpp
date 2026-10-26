// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/tx_collection.h>

#include <addresstype.h>
#include <bench/bench.h>
#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <key.h>
#include <node/miner.h>
#include <policy/feerate.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <txdb.h>
#include <uint256.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/translation.h>
#include <validation.h>

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <future>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#ifdef __linux__
#include <fcntl.h>
#include <unistd.h>
#endif

namespace {

#ifdef __linux__
constexpr bool EVICTS_OS_CACHE{true};
#else
constexpr bool EVICTS_OS_CACHE{false};
#endif

// Linux reports actual storage reads for the whole process, including workers.
// Other platforms still reset LevelDB, but do not evict or report the OS cache.
uint64_t StorageReadBytes()
{
#ifdef __linux__
    std::ifstream io{"/proc/self/io"};
    std::string name;
    uint64_t bytes;
    while (io >> name >> bytes) {
        if (name == "read_bytes:") return bytes;
    }
    Assert(false);
#endif
    return 0;
}

//! Number of transactions in the collection, and inputs per transaction. The
//! resulting template spends NUM_TXS * INPUTS_PER_TX coins from the UTXO set.
// Two taproot inputs and one taproot output per transaction produce a
// template above 99% of MAX_BLOCK_WEIGHT, including the generated coinbase.
constexpr size_t NUM_TXS{5900};
constexpr size_t INPUTS_PER_TX{2};

/** Common state for the TxCollection benchmarks: a chain whose UTXO set
 *  contains NUM_TXS * INPUTS_PER_TX confirmed and flushed-to-disk coins, and
 *  a set of valid transactions spending them. */
struct CollectionSetup {
    std::unique_ptr<TestChain100Setup> test_setup{MakeNoLogFileContext<TestChain100Setup>(ChainType::REGTEST, {.coins_db_in_memory = false})};
    std::vector<CTransactionRef> txs;
    std::vector<Wtxid> wtxids;
    std::vector<COutPoint> prevouts;
    uint256 tip;
    int64_t transaction_weight{0};

    explicit CollectionSetup(bool complete)
    {
        Chainstate& chainstate{test_setup->m_node.chainman->ActiveChainstate()};
        const CKey key{GenerateRandomKey()};
        const CTxOut txout{COIN / 1000, GetScriptForDestination(WitnessV1Taproot{XOnlyPubKey(key.GetPubKey())})};
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
        FillableSigningProvider keystore;
        keystore.AddKey(key);
        for (size_t i{0}; i < NUM_TXS; ++i) {
            CMutableTransaction tx;
            std::map<COutPoint, Coin> input_coins;
            for (size_t j{0}; j < INPUTS_PER_TX; ++j) {
                const COutPoint outpoint{funding_ref->GetHash(), static_cast<uint32_t>(i * INPUTS_PER_TX + j)};
                tx.vin.emplace_back(outpoint);
                input_coins.emplace(outpoint, Coin{txout, chainstate.m_chain.Height(), false});
                prevouts.push_back(outpoint);
            }
            tx.vout.push_back(txout);
            // Supply only these inputs to the signer, avoiding a quadratic
            // setup cost from caching every funding output for each spend.
            std::map<int, bilingual_str> input_errors;
            Assert(SignTransaction(tx, &keystore, input_coins, {.sighash_type = SIGHASH_ALL}, input_errors));
            txs.push_back(MakeTransactionRef(tx));
            wtxids.push_back(txs.back()->GetWitnessHash());
            transaction_weight += GetTransactionWeight(*txs.back());
        }

        chainstate.ForceFlushStateToDisk();
        // Move the generated coins out of LevelDB's memtable onto SST files.
        WITH_LOCK(cs_main, return chainstate.CoinsDB().CompactFullAsync()).wait();
        tip = WITH_LOCK(cs_main, return chainstate.m_chain.Tip()->GetBlockHash());
        for (size_t i{0}; i < txs.size() - (complete ? 0 : 1); ++i) {
            TryAddToMempool(*test_setup->m_node.mempool, TestMemPoolEntryHelper{}.Fee(COIN / 1000).FromTx(txs[i]));
        }
    }

    //! Reset caches before collection creation, outside the timed interval.
    void ResetCoinsCaches()
    {
        LOCK(cs_main);
        auto& chainstate{test_setup->m_node.chainman->ActiveChainstate()};
        for (const auto& outpoint : prevouts) chainstate.CoinsTip().Uncache(outpoint);
        // Reopen LevelDB to discard its block/table caches and old mappings,
        // preserving the regular coins cache's already allocated memory pool.
        // Startup metadata can be warm; subsequent input reads are measured.
        chainstate.CoinsDB().ResizeCache(chainstate.m_coinsdb_cache_size_bytes);
        const auto path{chainstate.StoragePath()};
#ifdef __linux__
        for (const auto& entry : fs::directory_iterator{path}) {
            if (!entry.is_regular_file()) continue;
            const int fd{open(entry.path().c_str(), O_RDONLY)};
            Assert(fd >= 0);
            Assert(fsync(fd) == 0);
            Assert(posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED) == 0);
            Assert(close(fd) == 0);
        }
#endif
    }
};


/** Keeping these helpers conditional lets the same benchmark-only commit run
 *  on the TxCollection baseline, without adding a production prefetch API there. */
template <typename Collection>
void WaitForKnownInputs(Collection& collection)
{
    if constexpr (requires { collection.WaitForPrefetch(); }) collection.WaitForPrefetch();
}

template <typename Collection>
std::pair<size_t, size_t> RetainedUsage(const Collection& collection)
{
    if constexpr (requires { collection.GetPrefetchInfo(); }) {
        const auto info{collection.GetPrefetchInfo()};
        return {info.coins, info.memory_usage};
    }
    return {};
}

enum class CollectionCase { COMPLETE,
                            PREPARE,
                            ONE_MISSING };

void BenchmarkCollection(benchmark::Bench& bench, CollectionCase mode)
{
    CollectionSetup setup{mode == CollectionCase::COMPLETE};
    std::unique_ptr<node::TxCollection> collection;
    std::unique_ptr<node::CBlockTemplate> block_template;
    size_t cache_entries_before{0}, cache_bytes_before{0};
    uint64_t storage_before{0}, storage_after_prep{0};
    std::string reason, debug;
    auto make_template = [&] {
        block_template = collection->MakeTemplate(setup.tip, nullptr, reason, debug);
        Assert(block_template);
    };
    auto prepare = [&] {
        block_template.reset();
        collection.reset();
        setup.ResetCoinsCaches();
        storage_before = storage_after_prep = StorageReadBytes();
        {
            LOCK(cs_main);
            const auto& coins{setup.test_setup->m_node.chainman->ActiveChainstate().CoinsTip()};
            cache_entries_before = coins.GetCacheSize();
            cache_bytes_before = coins.DynamicMemoryUsage();
        }
        if (mode == CollectionCase::COMPLETE || mode == CollectionCase::PREPARE) return;
        collection = std::make_unique<node::TxCollection>(setup.wtxids, *setup.test_setup->m_node.chainman, *setup.test_setup->m_node.mempool);
        Assert(collection->UnknownTxPos() == std::vector<uint32_t>{NUM_TXS - 1});
        if (mode == CollectionCase::ONE_MISSING) WaitForKnownInputs(*collection);
        storage_after_prep = StorageReadBytes();
    };
    auto operation = [&] {
        if (mode == CollectionCase::PREPARE) {
            collection = std::make_unique<node::TxCollection>(setup.wtxids, *setup.test_setup->m_node.chainman, *setup.test_setup->m_node.mempool);
            Assert(collection->UnknownTxPos() == std::vector<uint32_t>{NUM_TXS - 1});
            WaitForKnownInputs(*collection);
            return;
        }
        if (mode == CollectionCase::COMPLETE) {
            collection = std::make_unique<node::TxCollection>(setup.wtxids, *setup.test_setup->m_node.chainman, *setup.test_setup->m_node.mempool);
            Assert(collection->UnknownTxPos().empty());
        } else {
            collection->AddMissingTxs({setup.txs.back()});
        }
        make_template();
    };
    // Each timed sample has its own collection and a cold regular coins cache.
    // Respect the runner's one-epoch sanity mode; otherwise use 101 samples.
    if (bench.epochs() != 1) {
        for (unsigned i{0}; i < 5; ++i) {
            prepare();
            operation();
        }
        bench.epochs(101);
    }
    bench.unit(mode == CollectionCase::PREPARE ? "preparation" : "template").setup(prepare).run(operation);

    // Diagnostic state after the last sample, outside the timed operation.
    const auto storage_after{StorageReadBytes()};
    const auto [retained_entries, retained_bytes]{RetainedUsage(*collection)};
    const auto block_weight{block_template ? GetBlockWeight(block_template->block) : 0};
    if (block_template) Assert(block_weight > MAX_BLOCK_WEIGHT * 99 / 100 && block_weight <= MAX_BLOCK_WEIGHT);
    LOCK(cs_main);
    const auto& coins{setup.test_setup->m_node.chainman->ActiveChainstate().CoinsTip()};
    std::cout << "TXCOLLECTION_CACHE {\"benchmark\":\"" << bench.name()
              << "\",\"transactions\":" << setup.txs.size()
              << ",\"inputs\":" << setup.prevouts.size()
              << ",\"os_cache_eviction\":" << (EVICTS_OS_CACHE ? "true" : "false")
              << ",\"storage_read_bytes_prep\":" << storage_after_prep - storage_before
              << ",\"storage_read_bytes_timed\":" << storage_after - storage_after_prep
              << ",\"transaction_weight\":" << setup.transaction_weight
              << ",\"block_weight\":" << block_weight
              << ",\"coins_tip_entries_before\":" << cache_entries_before
              << ",\"coins_tip_entries_after\":" << coins.GetCacheSize()
              << ",\"coins_tip_bytes_before\":" << cache_bytes_before
              << ",\"coins_tip_bytes_after\":" << coins.DynamicMemoryUsage()
              << ",\"retained_entries\":" << retained_entries
              << ",\"retained_bytes\":" << retained_bytes << "}" << std::endl;
}

void TxCollectionComplete(benchmark::Bench& bench) { BenchmarkCollection(bench, CollectionCase::COMPLETE); }
void TxCollectionKnownInputPrep(benchmark::Bench& bench) { BenchmarkCollection(bench, CollectionCase::PREPARE); }
void TxCollectionOneMissing(benchmark::Bench& bench) { BenchmarkCollection(bench, CollectionCase::ONE_MISSING); }

} // namespace

BENCHMARK(TxCollectionComplete);
BENCHMARK(TxCollectionKnownInputPrep);
BENCHMARK(TxCollectionOneMissing);

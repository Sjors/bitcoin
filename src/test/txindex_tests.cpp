// Copyright (c) 2017-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <dbwrapper.h>
#include <flatfile.h>
#include <index/txindex.h>
#include <index/txindex_key.h>
#include <interfaces/chain.h>
#include <primitives/block.h>
#include <script/script.h>
#include <streams.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <util/byte_units.h>
#include <validation.h>

#include <cstdint>
#include <optional>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(txindex_tests)

class TxIndexTest
{
public:
    static CDBWrapper& GetDB(const BaseTransactionIndex& txindex) { return txindex.GetDB(); }
};

BOOST_FIXTURE_TEST_CASE(txindex_initial_sync, TestChain100Setup)
{
    TxIndex txindex(interfaces::MakeChain(m_node), 1_MiB, true);
    BOOST_REQUIRE(txindex.Init());

    CTransactionRef tx_disk;
    uint256 block_hash;

    // Transaction should not be found in the index before it is started.
    for (const auto& txn : m_coinbase_txns) {
        BOOST_CHECK(!txindex.FindTx(txn->GetHash(), block_hash, tx_disk));
    }

    // BlockUntilSyncedToCurrentChain should return false before txindex is started.
    BOOST_CHECK(!txindex.BlockUntilSyncedToCurrentChain());

    txindex.Sync();

    // Check that txindex excludes genesis block transactions.
    const CBlock& genesis_block = Params().GenesisBlock();
    for (const auto& txn : genesis_block.vtx) {
        BOOST_CHECK(!txindex.FindTx(txn->GetHash(), block_hash, tx_disk));
    }

    // Check that txindex has all txs that were in the chain before it started.
    for (const auto& txn : m_coinbase_txns) {
        if (!txindex.FindTx(txn->GetHash(), block_hash, tx_disk)) {
            BOOST_ERROR("FindTx failed");
        } else if (tx_disk->GetHash() != txn->GetHash()) {
            BOOST_ERROR("Read incorrect tx");
        }
    }

    // Check that new transactions in new blocks make it into the index.
    for (int i = 0; i < 10; i++) {
        CScript coinbase_script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
        std::vector<CMutableTransaction> no_txns;
        const CBlock& block = CreateAndProcessBlock(no_txns, coinbase_script_pub_key);
        const CTransaction& txn = *block.vtx[0];

        BOOST_CHECK(txindex.BlockUntilSyncedToCurrentChain());
        if (!txindex.FindTx(txn.GetHash(), block_hash, tx_disk)) {
            BOOST_ERROR("FindTx failed");
        } else if (tx_disk->GetHash() != txn.GetHash()) {
            BOOST_ERROR("Read incorrect tx");
        }
    }

    // shutdown sequence (c.f. Shutdown() in init.cpp)
    txindex.Stop();
}

BOOST_FIXTURE_TEST_CASE(wtxindex_initial_sync, TestChain100Setup)
{
    WtxIndex wtxindex(interfaces::MakeChain(m_node), 1_MiB, true);
    BOOST_REQUIRE(wtxindex.Init());

    CTransactionRef tx_disk;
    uint256 block_hash;

    // Transaction should not be found in the index before it is started.
    for (const auto& txn : m_coinbase_txns) {
        BOOST_CHECK(!wtxindex.FindTx(txn->GetWitnessHash(), block_hash, tx_disk));
    }

    // BlockUntilSyncedToCurrentChain should return false before wtxindex is started.
    BOOST_CHECK(!wtxindex.BlockUntilSyncedToCurrentChain());

    wtxindex.Sync();

    // Check that wtxindex excludes genesis block transactions.
    const CBlock& genesis_block = Params().GenesisBlock();
    for (const auto& txn : genesis_block.vtx) {
        BOOST_CHECK(!wtxindex.FindTx(txn->GetWitnessHash(), block_hash, tx_disk));
    }

    // Check that wtxindex has all txs that were in the chain before it started.
    for (const auto& txn : m_coinbase_txns) {
        if (!wtxindex.FindTx(txn->GetWitnessHash(), block_hash, tx_disk)) {
            BOOST_ERROR("FindTx failed");
        } else if (tx_disk->GetWitnessHash() != txn->GetWitnessHash()) {
            BOOST_ERROR("Read incorrect tx");
        }
    }

    // Check that new transactions in new blocks make it into the index.
    for (int i = 0; i < 10; i++) {
        CScript coinbase_script_pub_key = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
        std::vector<CMutableTransaction> no_txns;
        const CBlock& block = CreateAndProcessBlock(no_txns, coinbase_script_pub_key);
        const CTransaction& txn = *block.vtx[0];

        BOOST_CHECK(wtxindex.BlockUntilSyncedToCurrentChain());
        if (!wtxindex.FindTx(txn.GetWitnessHash(), block_hash, tx_disk)) {
            BOOST_ERROR("FindTx failed");
        } else if (tx_disk->GetWitnessHash() != txn.GetWitnessHash()) {
            BOOST_ERROR("Read incorrect tx");
        }
    }

    // shutdown sequence (c.f. Shutdown() in init.cpp)
    wtxindex.Stop();
}

BOOST_FIXTURE_TEST_CASE(wtxindex_collision_scan_path, TestChain100Setup)
{
    WtxIndex wtxindex(interfaces::MakeChain(m_node), 1_MiB, true);
    BOOST_REQUIRE(wtxindex.Init());
    wtxindex.Sync();

    CDBWrapper& db{TxIndexTest::GetDB(wtxindex)};
    std::pair<uint64_t, uint64_t> siphash_key;
    BOOST_REQUIRE(db.Read("siphash_key", siphash_key));
    const PresaltedSipHasher hasher{siphash_key.first, siphash_key.second};

    ChainstateManager& chainman{*m_node.chainman};
    const auto resolve_pos{[&](const txindex::Position& pos) -> std::optional<FlatFilePos> {
        LOCK(cs_main);
        const CBlockIndex* pindex{chainman.ActiveChain()[pos.block_height]};
        if (!pindex) return std::nullopt;
        const auto header_offset{static_cast<uint32_t>(GetSerializeSize(CBlockHeader{}))};
        return FlatFilePos{pindex->nFile, pindex->nDataPos + header_offset + pos.tx_offset};
    }};

    const auto read_wtxid{[&](const txindex::Position& position) -> std::optional<Wtxid> {
        const auto pos{resolve_pos(position)};
        if (!pos) return std::nullopt;
        AutoFile file{chainman.m_blockman.OpenBlockFile(*pos, true)};
        if (file.IsNull()) return std::nullopt;

        CTransactionRef tx;
        try {
            file >> TX_WITH_WITNESS(tx);
        } catch (const std::exception&) {
            return std::nullopt;
        }
        return tx->GetWitnessHash();
    }};

    const Wtxid fake_wtxid{m_coinbase_txns.front()->GetWitnessHash()};
    const Wtxid target_wtxid{m_coinbase_txns.at(1)->GetWitnessHash()};
    const auto fake_prefix{txindex::CreateKeyPrefix(hasher, fake_wtxid.ToUint256())};
    const auto target_prefix{txindex::CreateKeyPrefix(hasher, target_wtxid.ToUint256())};
    BOOST_REQUIRE(fake_prefix != target_prefix);

    std::unique_ptr<CDBIterator> it{db.NewIterator()};
    it->Seek(std::pair{txindex::DB_TXINDEX_HASHED, fake_prefix});
    txindex::DBKey key{fake_prefix, {}};
    BOOST_REQUIRE(it->Valid() && it->GetKey(key) && key.hash_prefix == fake_prefix);
    const txindex::Position fake_pos{key.pos};

    db.Write(txindex::DBKey{target_prefix, fake_pos}, "");

    it.reset(db.NewIterator());
    it->Seek(std::pair{txindex::DB_TXINDEX_HASHED, target_prefix});
    BOOST_REQUIRE(it->Valid() && it->GetKey(key) && key.hash_prefix == target_prefix);
    BOOST_CHECK(read_wtxid(key.pos) == fake_wtxid);
    it->Next();
    BOOST_REQUIRE(it->Valid() && it->GetKey(key) && key.hash_prefix == target_prefix);
    BOOST_CHECK(read_wtxid(key.pos) == target_wtxid);

    CTransactionRef tx_disk;
    uint256 block_hash;
    BOOST_REQUIRE(wtxindex.FindTx(target_wtxid, block_hash, tx_disk));
    BOOST_REQUIRE(tx_disk);
    BOOST_CHECK(tx_disk->GetWitnessHash() == target_wtxid);

    db.Erase(txindex::DBKey{target_prefix, fake_pos});
    wtxindex.Stop();
}

BOOST_FIXTURE_TEST_CASE(wtxindex_reorg_erases_entries, TestChain100Setup)
{
    WtxIndex wtxindex(interfaces::MakeChain(m_node), 1_MiB, true);
    BOOST_REQUIRE(wtxindex.Init());
    wtxindex.Sync();

    const CScript stale_coinbase_script{CScript() << OP_TRUE};
    const CBlock& stale_block{CreateAndProcessBlock({}, stale_coinbase_script)};
    const Wtxid stale_wtxid{stale_block.vtx.front()->GetWitnessHash()};
    BOOST_REQUIRE(wtxindex.BlockUntilSyncedToCurrentChain());

    CTransactionRef tx_disk;
    uint256 block_hash;
    BOOST_REQUIRE(wtxindex.FindTx(stale_wtxid, block_hash, tx_disk));
    BOOST_CHECK(tx_disk->GetWitnessHash() == stale_wtxid);
    const uint256 stale_block_hash{block_hash};

    ChainstateManager& chainman{*m_node.chainman};
    {
        CBlockIndex* tip{WITH_LOCK(cs_main, return chainman.ActiveChain().Tip())};
        BOOST_REQUIRE(tip->GetBlockHash() == stale_block_hash);
        BlockValidationState state;
        BOOST_REQUIRE(chainman.ActiveChainstate().InvalidateBlock(state, tip));
    }

    const CScript replacement_coinbase_script{CScript() << OP_FALSE};
    CreateAndProcessBlock({}, replacement_coinbase_script);
    CreateAndProcessBlock({}, replacement_coinbase_script);
    BOOST_REQUIRE(wtxindex.BlockUntilSyncedToCurrentChain());

    BOOST_CHECK(!wtxindex.FindTx(stale_wtxid, block_hash, tx_disk));

    wtxindex.Stop();
}

BOOST_AUTO_TEST_SUITE_END()

// Copyright (c) 2017-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <index/txindex.h>

#include <common/args.h>
#include <dbwrapper.h>
#include <flatfile.h>
#include <index/base.h>
#include <index/disktxpos.h>
#include <interfaces/chain.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/log.h>
#include <validation.h>

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <string>
#include <utility>
#include <vector>

constexpr uint8_t DB_TXINDEX{'t'};

std::unique_ptr<TxIndex> g_txindex;


/** Access to a transaction location index database. */
class BaseTransactionIndex::DB : public BaseIndex::DB
{
public:
    explicit DB(const fs::path& path, size_t n_cache_size, bool f_memory = false, bool f_wipe = false);
};

BaseTransactionIndex::DB::DB(const fs::path& path, size_t n_cache_size, bool f_memory, bool f_wipe) :
    BaseIndex::DB(path, n_cache_size, f_memory, f_wipe)
{}

BaseTransactionIndex::BaseTransactionIndex(std::unique_ptr<interfaces::Chain> chain, size_t n_cache_size, std::string index_name, std::string thread_name, const char* path_name, bool f_memory, bool f_wipe)
    : BaseIndex(std::move(chain), std::move(index_name), std::move(thread_name)),
      m_db(std::make_unique<BaseTransactionIndex::DB>(gArgs.GetDataDirNet() / "indexes" / path_name, n_cache_size, f_memory, f_wipe))
{}

BaseTransactionIndex::~BaseTransactionIndex() = default;

bool BaseTransactionIndex::CustomAppend(const interfaces::BlockInfo& block)
{
    // Exclude genesis block transaction because outputs are not spendable.
    if (block.height == 0) return true;

    assert(block.data);
    WriteBlock(block);
    return true;
}

BaseIndex::DB& BaseTransactionIndex::GetDB() const { return *m_db; }

bool BaseTransactionIndex::FindTx(const CDiskTxPos& postx, const std::function<bool(const CTransactionRef&)>& match_tx, uint256& block_hash, CTransactionRef& tx) const
{
    AutoFile file{m_chainstate->m_blockman.OpenBlockFile(postx, true)};
    if (file.IsNull()) {
        LogError("OpenBlockFile failed");
        return false;
    }
    CBlockHeader header;
    try {
        file >> header;
        file.seek(postx.nTxOffset, SEEK_CUR);
        file >> TX_WITH_WITNESS(tx);
    } catch (const std::exception& e) {
        LogError("Deserialize or I/O error - %s", e.what());
        return false;
    }
    if (!match_tx(tx)) {
        LogError("transaction index hash mismatch");
        return false;
    }
    block_hash = header.GetHash();
    return true;
}

TxIndex::TxIndex(std::unique_ptr<interfaces::Chain> chain, size_t n_cache_size, bool f_memory, bool f_wipe)
    : BaseTransactionIndex(std::move(chain), n_cache_size, "txindex", "txidx", "txindex", f_memory, f_wipe)
{}

TxIndex::~TxIndex() = default;

void TxIndex::WriteBlock(const interfaces::BlockInfo& block) const
{
    assert(block.data);
    CDBBatch batch(*m_db);
    CDiskTxPos pos({block.file_number, block.data_pos}, GetSizeOfCompactSize(block.data->vtx.size()));
    for (const auto& tx : block.data->vtx) {
        batch.Write(std::make_pair(DB_TXINDEX, tx->GetHash().ToUint256()), pos);
        pos.nTxOffset += ::GetSerializeSize(TX_WITH_WITNESS(*tx));
    }
    m_db->WriteBatch(batch);
}

bool TxIndex::FindTx(const Txid& tx_hash, uint256& block_hash, CTransactionRef& tx) const
{
    CDiskTxPos postx;
    if (!m_db->Read(std::make_pair(DB_TXINDEX, tx_hash.ToUint256()), postx)) {
        return false;
    }
    return BaseTransactionIndex::FindTx(postx, [&](const CTransactionRef& candidate) {
        return candidate->GetHash() == tx_hash;
    }, block_hash, tx);
}

// Copyright (c) 2017-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INDEX_TXINDEX_H
#define BITCOIN_INDEX_TXINDEX_H

#include <index/base.h>
#include <primitives/transaction.h>

#include <cstddef>
#include <functional>
#include <memory>
#include <string>

struct CDiskTxPos;
class uint256;
namespace interfaces {
class Chain;
}

static constexpr bool DEFAULT_TXINDEX{false};

/**
 * BaseTransactionIndex is used to look up transactions included in the blockchain by hash.
 * The index is written to a LevelDB database and records the filesystem
 * location of each transaction by a transaction identifier.
 */
class BaseTransactionIndex : public BaseIndex
{
protected:
    class DB;

    const std::unique_ptr<DB> m_db;

private:
    bool AllowPrune() const override { return false; }

protected:
    /// Constructs the index, which becomes available to be queried.
    explicit BaseTransactionIndex(std::unique_ptr<interfaces::Chain> chain, size_t n_cache_size, std::string index_name, std::string thread_name, const char* path_name, bool f_memory = false, bool f_wipe = false);

    /// Write the transaction locations for this index's key format.
    virtual void WriteBlock(const interfaces::BlockInfo& block) const = 0;

    bool CustomAppend(const interfaces::BlockInfo& block) override;

    BaseIndex::DB& GetDB() const override;

    /// Look up a transaction by disk position and confirm it matches.
    bool FindTx(const CDiskTxPos& postx, const std::function<bool(const CTransactionRef&)>& match_tx, uint256& block_hash, CTransactionRef& tx) const;

public:
    // Destructor is declared because this class contains a unique_ptr to an incomplete type.
    virtual ~BaseTransactionIndex() override;
};

/**
 * TxIndex is used to look up transactions included in the blockchain by txid.
 */
class TxIndex final : public BaseTransactionIndex
{
protected:
    void WriteBlock(const interfaces::BlockInfo& block) const override;

public:
    /// Constructs the index, which becomes available to be queried.
    explicit TxIndex(std::unique_ptr<interfaces::Chain> chain, size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    virtual ~TxIndex() override;

    /// Look up a transaction by txid.
    ///
    /// @param[in]   tx_hash  The hash of the transaction to be returned.
    /// @param[out]  block_hash  The hash of the block the transaction is found in.
    /// @param[out]  tx  The transaction itself.
    /// @return  true if transaction is found, false otherwise
    bool FindTx(const Txid& tx_hash, uint256& block_hash, CTransactionRef& tx) const;
};

/// The global transaction index, used in GetTransaction. May be null.
extern std::unique_ptr<TxIndex> g_txindex;

#endif // BITCOIN_INDEX_TXINDEX_H

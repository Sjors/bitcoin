// Copyright (c) 2017-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INDEX_TXINDEX_H
#define BITCOIN_INDEX_TXINDEX_H

#include <index/base.h>
#include <kernel/chain.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <cstddef>
#include <memory>
#include <optional>
#include <string>

namespace interfaces {
class Chain;
}
namespace txindex_tests {
class TxIndexTest;
}

inline constexpr bool DEFAULT_TXINDEX{false};
inline constexpr bool DEFAULT_WTXINDEX{false};

/// A found transaction and the hash of the block that contains it.
struct TxIndexResult {
    uint256 block_hash;
    CTransactionRef tx;
};

/**
 * BaseTransactionIndex is used to look up transactions included in the blockchain by hash.
 * The index is written to a LevelDB database and records the block sequence
 * number and serialized block offset of each transaction by transaction identifier.
 */
class BaseTransactionIndex : public BaseIndex
{
protected:
    class DB;

private:
    friend class txindex_tests::TxIndexTest;

protected:
    const std::unique_ptr<DB> m_db;

private:
    bool AllowPrune() const override { return false; }

protected:
    /// Constructs the index, which becomes available to be queried.
    explicit BaseTransactionIndex(std::unique_ptr<interfaces::Chain> chain, size_t n_cache_size, std::string index_name, std::string thread_name, const char* path_name, bool has_legacy, bool f_memory = false, bool f_wipe = false);

    /// Write the transaction locations for this index's key format.
    void WriteBlock(const interfaces::BlockInfo& block) const;

    /// Return the identifier this index uses for a transaction.
    virtual uint256 GetHash(const CTransaction& tx) const = 0;

    bool CustomAppend(const interfaces::BlockInfo& block) override;

    BaseIndex::DB& GetDB() const override;

    /// Look up a transaction by its index-specific identifier.
    std::optional<TxIndexResult> FindTx(const uint256& tx_hash, bool active_only) const;

public:
    // Destructor is declared because this class contains a unique_ptr to an incomplete type.
    virtual ~BaseTransactionIndex() override;
};

/**
 * TxIndex is used to look up transactions included in the blockchain by txid.
 */
class TxIndex final : public BaseTransactionIndex
{
private:
    uint256 GetHash(const CTransaction& tx) const override { return tx.GetHash().ToUint256(); }

    /// Look up a transaction among the legacy (full-txid) entries.
    std::optional<TxIndexResult> FindLegacyTx(const Txid& tx_hash) const;

public:
    /// Constructs the index, which becomes available to be queried.
    explicit TxIndex(std::unique_ptr<interfaces::Chain> chain, size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    virtual ~TxIndex() override;

    /// Look up a transaction by txid.
    ///
    /// @param[in]   tx_hash  The hash of the transaction to be returned.
    /// @return  the transaction and containing block hash, or nullopt if it is not found
    std::optional<TxIndexResult> FindTx(const Txid& tx_hash) const;
};

/**
 * WtxIndex is used to look up transactions included in the blockchain by wtxid.
 */
class WtxIndex final : public BaseTransactionIndex
{
private:
    uint256 GetHash(const CTransaction& tx) const override { return tx.GetWitnessHash().ToUint256(); }

public:
    /// Constructs the index, which becomes available to be queried.
    explicit WtxIndex(std::unique_ptr<interfaces::Chain> chain, size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    virtual ~WtxIndex() override;

    /// Look up a transaction by wtxid.
    ///
    /// @param[in]   wtx_hash  The witness hash of the transaction to be returned.
    /// @return  the transaction and containing block hash, or nullopt if it is not found
    std::optional<TxIndexResult> FindTx(const Wtxid& wtx_hash) const;
};

/// The global transaction index, used in GetTransaction. May be null.
extern std::unique_ptr<TxIndex> g_txindex;
/// The global witness transaction index. May be null.
extern std::unique_ptr<WtxIndex> g_wtxindex;

#endif // BITCOIN_INDEX_TXINDEX_H

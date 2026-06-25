// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#ifndef BITCOIN_NODE_TXPROOF_H
#define BITCOIN_NODE_TXPROOF_H

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <primitives/transaction_identifier.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <vector>

namespace node {

struct TxProofTransaction {
    Txid txid;
    Wtxid wtxid;
    uint32_t pos{0};
    std::optional<std::vector<uint256>> txid_branch;
    std::optional<std::vector<uint256>> wtxid_branch;
};

struct TxProof {
    uint256 block_hash;
    uint32_t block_tx_count{0};
    CTransactionRef coinbase;
    std::vector<TxProofTransaction> transactions;
};

struct TxProofVerificationTransaction {
    uint32_t pos{0};
    std::optional<Txid> txid;
    std::optional<Wtxid> wtxid;
};

struct TxProofVerificationResult {
    uint256 block_hash;
    uint32_t block_tx_count{0};
    std::vector<TxProofVerificationTransaction> transactions;
};

std::optional<TxProof> MakeTxProof(const CBlock& block, const std::optional<Wtxid>& wtxid);
std::optional<TxProofVerificationResult> VerifyTxProof(const TxProof& proof, const CBlockHeader& header, uint32_t block_tx_count);

} // namespace node

#endif // BITCOIN_NODE_TXPROOF_H

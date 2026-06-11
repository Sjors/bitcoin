// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <node/txproof.h>

#include <common/merkle.h>
#include <consensus/validation.h>
#include <hash.h>
#include <util/check.h>

#include <cstring>
#include <limits>
#include <set>

namespace node {
namespace {

bool VerifyMerkleBranch(const uint256& root, const uint256& leaf, const std::vector<uint256>& branch, uint32_t pos, uint32_t tx_count)
{
    const auto computed_root{ComputeMerkleRootFromBranch(leaf, branch, pos, tx_count)};
    return computed_root && *computed_root == root;
}

bool VerifyWitnessCommitment(const CTransaction& coinbase, const uint256& witness_root)
{
    const int witness_commitment_index{GetWitnessCommitmentIndex(coinbase)};
    if (witness_commitment_index == NO_WITNESS_COMMITMENT) return false;

    const auto& witness_stack{coinbase.vin[0].scriptWitness.stack};
    if (witness_stack.size() != 1 || witness_stack[0].size() != 32) return false;

    uint256 commitment{witness_root};
    CHash256().Write(commitment).Write(witness_stack[0]).Finalize(commitment);
    return memcmp(commitment.begin(), &coinbase.vout[witness_commitment_index].scriptPubKey[6], 32) == 0;
}

} // namespace

std::optional<TxProof> MakeTxProof(const CBlock& block, const std::optional<Wtxid>& wtxid)
{
    if (block.vtx.empty() || block.vtx.size() > std::numeric_limits<uint32_t>::max()) return std::nullopt;

    TxProof proof;
    proof.block_hash = block.GetHash();
    proof.block_tx_count = static_cast<uint32_t>(block.vtx.size());
    proof.coinbase = block.vtx[0];

    TxProofTransaction coinbase;
    coinbase.txid = proof.coinbase->GetHash();
    coinbase.wtxid = proof.coinbase->GetWitnessHash();
    coinbase.pos = 0;
    coinbase.txid_branch = TransactionMerklePath(block, /*position=*/0);
    proof.transactions.push_back(std::move(coinbase));

    if (!wtxid || *wtxid == proof.coinbase->GetWitnessHash()) return proof;

    const bool has_witness_commitment{GetWitnessCommitmentIndex(block) != NO_WITNESS_COMMITMENT};
    for (size_t i{1}; i < block.vtx.size(); ++i) {
        const Txid txid{block.vtx[i]->GetHash()};
        const Wtxid block_wtxid{block.vtx[i]->GetWitnessHash()};
        if (*wtxid != block_wtxid) continue;

        TxProofTransaction transaction;
        transaction.txid = txid;
        transaction.wtxid = block_wtxid;
        transaction.pos = static_cast<uint32_t>(i);
        if (has_witness_commitment) {
            transaction.wtxid_branch = WitnessMerklePath(block, i);
        } else {
            transaction.txid_branch = TransactionMerklePath(block, i);
        }
        proof.transactions.push_back(std::move(transaction));
        return proof;
    }

    return std::nullopt;
}

std::optional<TxProofVerificationResult> VerifyTxProof(const TxProof& proof, const CBlockHeader& header, uint32_t block_tx_count)
{
    if (block_tx_count == 0) return std::nullopt;
    if (!proof.coinbase || !proof.coinbase->IsCoinBase()) return std::nullopt;
    if (proof.block_hash != header.GetHash()) return std::nullopt;
    if (proof.block_tx_count != block_tx_count) return std::nullopt;
    if (proof.transactions.empty()) return std::nullopt;

    const bool has_witness_commitment{GetWitnessCommitmentIndex(*proof.coinbase) != NO_WITNESS_COMMITMENT};
    TxProofVerificationResult result;
    result.block_hash = proof.block_hash;
    result.block_tx_count = proof.block_tx_count;
    result.transactions.reserve(proof.transactions.size());

    bool has_coinbase{false};
    std::set<uint32_t> positions;
    for (const auto& transaction : proof.transactions) {
        if (transaction.pos >= proof.block_tx_count) return std::nullopt;
        if (!positions.insert(transaction.pos).second) return std::nullopt;

        TxProofVerificationTransaction verified;
        verified.pos = transaction.pos;

        if (transaction.pos == 0) {
            if (has_coinbase) return std::nullopt;
            if (!transaction.txid_branch || transaction.wtxid_branch) return std::nullopt;
            if (transaction.txid != proof.coinbase->GetHash()) return std::nullopt;
            if (transaction.wtxid != proof.coinbase->GetWitnessHash()) return std::nullopt;
            if (!VerifyMerkleBranch(header.hashMerkleRoot, transaction.txid.ToUint256(), *transaction.txid_branch, transaction.pos, proof.block_tx_count)) {
                return std::nullopt;
            }
            verified.txid = transaction.txid;
            if (!has_witness_commitment || transaction.txid.ToUint256() == transaction.wtxid.ToUint256()) {
                verified.wtxid = transaction.wtxid;
            }
            has_coinbase = true;
            result.transactions.push_back(std::move(verified));
            continue;
        }

        if (has_witness_commitment) {
            if (!transaction.wtxid_branch || transaction.txid_branch) return std::nullopt;
            const auto witness_root{ComputeMerkleRootFromBranch(transaction.wtxid.ToUint256(), *transaction.wtxid_branch, transaction.pos, proof.block_tx_count)};
            if (!witness_root || !VerifyWitnessCommitment(*proof.coinbase, *witness_root)) return std::nullopt;
            verified.wtxid = transaction.wtxid;
            result.transactions.push_back(std::move(verified));
            continue;
        }

        if (!transaction.txid_branch || transaction.wtxid_branch) return std::nullopt;
        if (transaction.txid.ToUint256() != transaction.wtxid.ToUint256()) return std::nullopt;
        if (!VerifyMerkleBranch(header.hashMerkleRoot, transaction.txid.ToUint256(), *transaction.txid_branch, transaction.pos, proof.block_tx_count)) {
            return std::nullopt;
        }
        verified.txid = transaction.txid;
        verified.wtxid = transaction.wtxid;
        result.transactions.push_back(std::move(verified));
    }

    if (!has_coinbase) return std::nullopt;
    return result;
}

} // namespace node

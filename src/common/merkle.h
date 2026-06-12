// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMMON_MERKLE_H
#define BITCOIN_COMMON_MERKLE_H

#include <primitives/block.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <vector>

/**
 * Compute the Merkle root for a leaf from a merkle branch and a known tree
 * shape, or nullopt if the branch is inconsistent with the supplied position
 * and leaf count.
 */
std::optional<uint256> ComputeMerkleRootFromBranch(const uint256& leaf, const std::vector<uint256>& branch, uint32_t position, uint32_t leaf_count);

/**
 * Compute merkle path to the specified transaction
 *
 * @param[in] block the block
 * @param[in] position transaction for which to calculate the merkle path (0 is the coinbase)
 *
 * @return merkle path ordered from the deepest
 */
std::vector<uint256> TransactionMerklePath(const CBlock& block, uint32_t position);

#endif // BITCOIN_COMMON_MERKLE_H

// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_ENCRYPTED_BACKUP_H
#define BITCOIN_WALLET_ENCRYPTED_BACKUP_H

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include <pubkey.h>
#include <uint256.h>
#include <util/result.h>

namespace wallet {

/**
 * Implements the encrypted backup scheme from BIP 138.
 *
 * This provides encryption for wallet descriptors, labels, and other metadata
 * that can be safely stored in untrusted locations. The encryption key is derived
 * from the public keys in the descriptor, allowing any keyholder to decrypt
 * without additional secrets.
 *
 * IMPORTANT: This format intentionally does NOT backup private key material.
 * Restoring from an encrypted backup creates a watch-only wallet.
 */

/** Prefix for deriving the decryption secret */
static constexpr std::string_view BIP_DECRYPTION_SECRET_TAG = "BIP138_DECRYPTION_SECRET";

/** Prefix for deriving individual secrets */
static constexpr std::string_view BIP_INDIVIDUAL_SECRET_TAG = "BIP138_INDIVIDUAL_SECRET";

/**
 * Represents a parsed derivation path (e.g., m/44'/0'/0').
 * Each element is a 32-bit child index where hardened indices have the high bit set.
 */
using DerivationPath = std::vector<uint32_t>;

/**
 * Extract and normalize all eligible extended public keys from a descriptor string.
 *
 * Extended public keys that are not directly observable from descriptor spends
 * are used. Literal public keys, directly observable xpubs, and the NUMS point
 * are excluded. Keys are sorted lexicographically and deduplicated.
 *
 * @param[in] descriptor The descriptor string
 * @return Vector of normalized x-only public keys, or error message
 */
util::Result<std::vector<XOnlyPubKey>> ExtractKeysFromDescriptor(const std::string& descriptor);

/**
 * Compute the decryption secret from a set of public keys.
 *
 * s = TaggedHash("BIP138_DECRYPTION_SECRET", p1 || p2 || ... || pn)
 * where p1...pn are sorted lexicographically.
 *
 * @param[in] keys The normalized x-only public keys (must be sorted)
 * @return The 32-byte decryption secret
 */
uint256 ComputeDecryptionSecret(const std::vector<XOnlyPubKey>& keys);

/**
 * Compute an individual secret for a specific public key.
 *
 * si = TaggedHash("BIP138_INDIVIDUAL_SECRET", pi)
 *
 * @param[in] key The normalized x-only public key
 * @return The 32-byte individual secret
 */
uint256 ComputeIndividualSecret(const XOnlyPubKey& key);

/**
 * Compute all individual secrets from the decryption secret and keys.
 *
 * ci = s XOR si
 *
 * @param[in] decryption_secret The decryption secret
 * @param[in] keys The normalized x-only public keys
 * @return Vector of individual secrets (ci values)
 */
std::vector<uint256> ComputeAllIndividualSecrets(const uint256& decryption_secret,
                                                  const std::vector<XOnlyPubKey>& keys);

/**
 * Encode derivation paths according to the backup format.
 *
 * @param[in] paths Vector of derivation paths
 * @return Encoded bytes, or error if too many paths
 */
util::Result<std::vector<uint8_t>> EncodeDerivationPaths(const std::vector<DerivationPath>& paths);

/**
 * Decode derivation paths from backup format.
 *
 * @param[in] data The encoded data
 * @return Vector of derivation paths, or error message
 */
util::Result<std::vector<DerivationPath>> DecodeDerivationPaths(std::span<const uint8_t> data);

} // namespace wallet

#endif // BITCOIN_WALLET_ENCRYPTED_BACKUP_H

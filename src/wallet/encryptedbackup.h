// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_ENCRYPTEDBACKUP_H
#define BITCOIN_WALLET_ENCRYPTEDBACKUP_H

#include <cstdint>
#include <string>
#include <vector>

#include <pubkey.h>
#include <uint256.h>
#include <util/result.h>

namespace wallet {

/**
 * Implements the encrypted backup scheme from BIP-XXXX (draft).
 *
 * This provides encryption for wallet descriptors, labels, and other metadata
 * that can be safely stored in untrusted locations. The encryption key is derived
 * from the public keys in the descriptor, allowing any keyholder to decrypt
 * without additional secrets.
 *
 * IMPORTANT: This format intentionally does NOT backup private key material.
 * Restoring from an encrypted backup creates a watch-only wallet.
 */

/**
 * Normalize a public key to 32-byte x-only format.
 *
 * Handles:
 * - Extended public keys (xpubs): extracts the pubkey and returns x-coordinate
 * - Compressed public keys (33 bytes): strips the prefix byte
 * - X-only public keys (32 bytes): returns as-is
 * - Uncompressed public keys (65 bytes): extracts the x-coordinate
 *
 * @param[in] pubkey The public key to normalize
 * @return The 32-byte x-only representation
 */
uint256 NormalizeToXOnly(const CPubKey& pubkey);

/**
 * Normalize an extended public key to 32-byte x-only format.
 *
 * @param[in] xpub The extended public key to normalize
 * @return The 32-byte x-only representation of the root pubkey
 */
uint256 NormalizeToXOnly(const CExtPubKey& xpub);

/**
 * Check if an x-only key is the BIP341 NUMS point (unspendable).
 *
 * @param[in] key The x-only key to check
 * @return true if this is the NUMS point
 */
bool IsNUMSPoint(const uint256& key);

/**
 * Extract and normalize all public keys from a descriptor string.
 *
 * Keys are sorted lexicographically and deduplicated. The NUMS point is excluded.
 *
 * @param[in] descriptor The descriptor string
 * @return Vector of normalized x-only public keys, or error message
 */
util::Result<std::vector<uint256>> ExtractKeysFromDescriptor(const std::string& descriptor);

} // namespace wallet

#endif // BITCOIN_WALLET_ENCRYPTEDBACKUP_H

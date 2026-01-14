// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_ENCRYPTED_BACKUP_H
#define BITCOIN_WALLET_ENCRYPTED_BACKUP_H

#include <cstdint>
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

} // namespace wallet

#endif // BITCOIN_WALLET_ENCRYPTED_BACKUP_H

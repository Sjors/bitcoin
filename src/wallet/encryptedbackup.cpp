// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/encryptedbackup.h>

#include <cstring>

#include <key_io.h>
#include <script/descriptor.h>

namespace wallet {

uint256 NormalizeToXOnly(const CPubKey& pubkey)
{
    // CPubKey is either compressed (33 bytes) or uncompressed (65 bytes)
    // In both cases, bytes 1-32 are the x-coordinate
    uint256 result;
    if (pubkey.size() >= 33) {
        std::memcpy(result.data(), pubkey.data() + 1, 32);
    }
    return result;
}

uint256 NormalizeToXOnly(const CExtPubKey& xpub)
{
    return NormalizeToXOnly(xpub.pubkey);
}

bool IsNUMSPoint(const uint256& key)
{
    // BIP341 NUMS point: 50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0
    // Compare against XOnlyPubKey::NUMS_H
    XOnlyPubKey xonly{std::span<const unsigned char>{key.data(), 32}};
    return xonly == XOnlyPubKey::NUMS_H;
}

util::Result<std::vector<uint256>> ExtractKeysFromDescriptor(const std::string& descriptor)
{
    FlatSigningProvider provider;
    std::string error;
    auto parsed = Parse(descriptor, provider, error, /*require_checksum=*/false);
    if (parsed.empty()) {
        return util::Error{Untranslated(strprintf("Failed to parse descriptor: %s", error))};
    }

    std::set<CPubKey> pubkeys;
    std::set<CExtPubKey> xpubs;
    for (const auto& desc : parsed) {
        desc->GetPubKeys(pubkeys, xpubs);
    }

    // Normalize all keys to x-only format
    std::set<uint256> normalized_keys;
    for (const auto& pubkey : pubkeys) {
        uint256 xonly = NormalizeToXOnly(pubkey);
        // Skip NUMS point
        if (!IsNUMSPoint(xonly)) {
            normalized_keys.insert(xonly);
        }
    }
    for (const auto& xpub : xpubs) {
        uint256 xonly = NormalizeToXOnly(xpub);
        // Skip NUMS point
        if (!IsNUMSPoint(xonly)) {
            normalized_keys.insert(xonly);
        }
    }

    if (normalized_keys.empty()) {
        return util::Error{Untranslated("No valid public keys found in descriptor")};
    }

    // Convert set to sorted vector (set is already sorted)
    return std::vector<uint256>(normalized_keys.begin(), normalized_keys.end());
}

} // namespace wallet

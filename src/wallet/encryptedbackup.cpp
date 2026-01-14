// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/encryptedbackup.h>

#include <cstring>

#include <hash.h>
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

uint256 ComputeDecryptionSecret(const std::vector<uint256>& keys)
{
    // s = sha256("BIP_XXXX_DECRYPTION_SECRET" || p1 || p2 || ... || pn)
    HashWriter hasher{};
    hasher << std::span{reinterpret_cast<const uint8_t*>(BIP_DECRYPTION_SECRET_TAG.data()),
                        BIP_DECRYPTION_SECRET_TAG.size()};
    for (const auto& key : keys) {
        hasher << std::span{key.data(), 32};
    }
    return hasher.GetSHA256();
}

uint256 ComputeIndividualSecret(const uint256& key)
{
    // si = sha256("BIP_XXXX_INDIVIDUAL_SECRET" || pi)
    HashWriter hasher{};
    hasher << std::span{reinterpret_cast<const uint8_t*>(BIP_INDIVIDUAL_SECRET_TAG.data()),
                        BIP_INDIVIDUAL_SECRET_TAG.size()};
    hasher << std::span{key.data(), 32};
    return hasher.GetSHA256();
}

std::vector<uint256> ComputeAllIndividualSecrets(const uint256& decryption_secret,
                                                  const std::vector<uint256>& keys)
{
    std::vector<uint256> result;
    result.reserve(keys.size());

    for (const auto& key : keys) {
        // si = sha256("BIP_XXXX_INDIVIDUAL_SECRET" || pi)
        uint256 si = ComputeIndividualSecret(key);
        // ci = s XOR si
        uint256 ci;
        for (size_t i = 0; i < 32; ++i) {
            ci.data()[i] = decryption_secret.data()[i] ^ si.data()[i];
        }
        result.push_back(ci);
    }
    return result;
}

} // namespace wallet

// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/encrypted_backup.h>

#include <algorithm>
#include <set>
#include <span>

#include <hash.h>
#include <script/descriptor.h>
#include <util/bip32.h>

namespace wallet {

util::Result<std::vector<XOnlyPubKey>> ExtractKeysFromDescriptor(const std::string& descriptor)
{
    FlatSigningProvider provider;
    std::string error;
    auto parsed = Parse(descriptor, provider, error, /*require_checksum=*/false);
    if (parsed.empty()) {
        return util::Error{Untranslated(strprintf("Failed to parse descriptor: %s", error))};
    }

    // Only BIP32 public key expressions that are not directly observable from
    // descriptor spends contribute to the encryption key set.
    std::set<XOnlyPubKey> normalized_keys;
    for (const auto& desc : parsed) {
        std::set<CExtPubKey> ext_pubkeys;
        desc->GetExtPubKeys(ext_pubkeys, /*exclude_observable=*/true);
        for (const auto& ext_pubkey : ext_pubkeys) {
            const XOnlyPubKey xonly{ext_pubkey.pubkey};
            if (xonly == XOnlyPubKey::NUMS_H) continue;
            normalized_keys.insert(xonly);
        }
    }

    if (normalized_keys.empty()) {
        return util::Error{Untranslated("No valid extended public keys with trailing derivation found in descriptor")};
    }

    return std::vector<XOnlyPubKey>(normalized_keys.begin(), normalized_keys.end());
}

uint256 ComputeDecryptionSecret(const std::vector<XOnlyPubKey>& keys)
{
    // s = TaggedHash("BIP138_DECRYPTION_SECRET", p1 || p2 || ... || pn)
    HashWriter hasher{TaggedHash(std::string{BIP_DECRYPTION_SECRET_TAG})};
    for (const auto& key : keys) {
        hasher << std::span{key.data(), XOnlyPubKey::size()};
    }
    return hasher.GetSHA256();
}

uint256 ComputeIndividualSecret(const XOnlyPubKey& key)
{
    // si = TaggedHash("BIP138_INDIVIDUAL_SECRET", pi)
    HashWriter hasher{TaggedHash(std::string{BIP_INDIVIDUAL_SECRET_TAG})};
    hasher << std::span{key.data(), XOnlyPubKey::size()};
    return hasher.GetSHA256();
}

std::vector<uint256> ComputeAllIndividualSecrets(const uint256& decryption_secret,
                                                  const std::vector<XOnlyPubKey>& keys)
{
    std::vector<uint256> result;
    result.reserve(keys.size());

    for (const auto& key : keys) {
        // si = TaggedHash("BIP138_INDIVIDUAL_SECRET", pi)
        uint256 si = ComputeIndividualSecret(key);
        // ci = s XOR si
        uint256 ci;
        std::transform(decryption_secret.begin(), decryption_secret.end(), si.begin(), ci.begin(),
                       [](uint8_t a, uint8_t b) { return a ^ b; });
        result.push_back(ci);
    }
    return result;
}

util::Result<std::vector<uint8_t>> EncodeDerivationPaths(const std::vector<DerivationPath>& paths)
{
    if (paths.size() > 255) {
        return util::Error{Untranslated("Too many derivation paths (max 255)")};
    }

    std::vector<uint8_t> result;
    result.push_back(static_cast<uint8_t>(paths.size()));

    auto sorted_paths{paths};
    std::sort(sorted_paths.begin(), sorted_paths.end());

    for (const auto& path : sorted_paths) {
        if (path.empty()) {
            return util::Error{Untranslated("Derivation path must contain at least one child")};
        }
        if (path.size() > 255) {
            return util::Error{Untranslated("Derivation path too long (max 255 components)")};
        }
        result.push_back(static_cast<uint8_t>(path.size()));
        for (uint32_t child : path) {
            // Big-endian encoding
            result.push_back((child >> 24) & 0xFF);
            result.push_back((child >> 16) & 0xFF);
            result.push_back((child >> 8) & 0xFF);
            result.push_back(child & 0xFF);
        }
    }

    return result;
}

util::Result<std::vector<DerivationPath>> DecodeDerivationPaths(std::span<const uint8_t> data)
{
    if (data.empty()) {
        return util::Error{Untranslated("Empty derivation paths data")};
    }

    std::vector<DerivationPath> result;
    size_t pos = 0;

    uint8_t count = data[pos++];
    result.reserve(count);

    for (uint8_t i = 0; i < count; ++i) {
        if (pos >= data.size()) {
            return util::Error{Untranslated("Truncated derivation path data")};
        }

        uint8_t child_count = data[pos++];
        if (child_count == 0) {
            return util::Error{Untranslated("Derivation path must contain at least one child")};
        }
        DerivationPath path;
        path.reserve(child_count);

        for (uint8_t j = 0; j < child_count; ++j) {
            if (pos + 4 > data.size()) {
                return util::Error{Untranslated("Truncated child index")};
            }
            uint32_t child = (static_cast<uint32_t>(data[pos]) << 24) |
                            (static_cast<uint32_t>(data[pos + 1]) << 16) |
                            (static_cast<uint32_t>(data[pos + 2]) << 8) |
                            static_cast<uint32_t>(data[pos + 3]);
            pos += 4;
            path.push_back(child);
        }
        result.push_back(std::move(path));
    }

    return result;
}

} // namespace wallet

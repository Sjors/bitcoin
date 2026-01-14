// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/encrypted_backup.h>

#include <algorithm>
#include <set>
#include <span>

#include <hash.h>
#include <key_io.h>
#include <script/descriptor.h>
#include <util/bip32.h>
#include <util/strencodings.h>
#include <util/string.h>

namespace wallet {

util::Result<std::vector<XOnlyPubKey>> ExtractKeysFromDescriptor(const std::string& descriptor,
                                                                 std::set<std::string>* excluded_expressions)
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

        if (excluded_expressions) {
            // Literal pubkeys are always excluded; xpubs are excluded when
            // observable from spends. The NUMS point is not reported, since
            // no cosigner holds it.
            std::set<CPubKey> all_pubkeys;
            std::set<CExtPubKey> all_ext_pubkeys;
            // Classify each occurrence before deduplicating: the same xpub
            // may appear both bare and with trailing derivation.
            desc->GetPubKeys(all_pubkeys, all_ext_pubkeys, /*only_observable=*/true);
            for (const auto& pubkey : all_pubkeys) {
                if (XOnlyPubKey{pubkey} == XOnlyPubKey::NUMS_H) continue;
                excluded_expressions->insert(HexStr(pubkey));
            }
            for (const auto& ext_pubkey : all_ext_pubkeys) {
                if (XOnlyPubKey{ext_pubkey.pubkey} == XOnlyPubKey::NUMS_H) continue;
                excluded_expressions->insert(EncodeExtPubKey(ext_pubkey));
            }
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

bool IsCommonDerivationPath(const DerivationPath& path)
{
    constexpr uint32_t HARDENED{0x80000000};
    if (path.size() != 3 && path.size() != 4) return false;
    const uint32_t purpose{path[0]};
    // Coin type 0 (mainnet) or 1 (test networks)
    if (path[1] != HARDENED && path[1] != (1 | HARDENED)) return false;
    // Accounts 0 through 9
    if (path[2] < HARDENED || path[2] > (9 | HARDENED)) return false;
    if (path.size() == 3) {
        return purpose == (44 | HARDENED) || purpose == (49 | HARDENED) ||
               purpose == (84 | HARDENED) || purpose == (86 | HARDENED) ||
               purpose == (87 | HARDENED);
    }
    return purpose == (48 | HARDENED) && (path[3] == (1 | HARDENED) || path[3] == (2 | HARDENED));
}

std::vector<DerivationPath> CommonDerivationPaths()
{
    constexpr uint32_t HARDENED{0x80000000};
    std::vector<DerivationPath> paths;
    for (uint32_t coin{0}; coin <= 1; ++coin) {
        for (uint32_t account{0}; account <= 9; ++account) {
            for (uint32_t purpose : {44, 49, 84, 86, 87}) {
                paths.push_back({purpose | HARDENED, coin | HARDENED, account | HARDENED});
            }
            for (uint32_t script_type{1}; script_type <= 2; ++script_type) {
                paths.push_back({48 | HARDENED, coin | HARDENED, account | HARDENED, script_type | HARDENED});
            }
        }
    }
    return paths;
}

util::Result<std::vector<uint8_t>> EncodeDerivationPaths(const std::vector<DerivationPath>& paths)
{
    // Sort lexicographically and deduplicate for consistent encoding
    auto sorted_paths{paths};
    std::sort(sorted_paths.begin(), sorted_paths.end());
    sorted_paths.erase(std::unique(sorted_paths.begin(), sorted_paths.end()), sorted_paths.end());

    if (sorted_paths.size() > 255) {
        return util::Error{Untranslated("Too many derivation paths (max 255)")};
    }

    std::vector<uint8_t> result;
    result.push_back(static_cast<uint8_t>(sorted_paths.size()));

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

util::Result<std::vector<uint8_t>> EncodeIndividualSecrets(const std::vector<uint256>& secrets)
{
    if (secrets.empty()) {
        return util::Error{Untranslated("At least one individual secret is required")};
    }

    // Sort secrets lexicographically and deduplicate for consistent encoding
    std::vector<uint256> sorted_secrets = secrets;
    std::sort(sorted_secrets.begin(), sorted_secrets.end());
    sorted_secrets.erase(std::unique(sorted_secrets.begin(), sorted_secrets.end()), sorted_secrets.end());

    if (sorted_secrets.size() > 255) {
        return util::Error{Untranslated("Too many individual secrets (max 255)")};
    }

    std::vector<uint8_t> result;
    result.reserve(1 + sorted_secrets.size() * 32);
    result.push_back(static_cast<uint8_t>(sorted_secrets.size()));

    for (const auto& secret : sorted_secrets) {
        result.insert(result.end(), secret.begin(), secret.end());
    }

    return result;
}

util::Result<std::vector<uint256>> DecodeIndividualSecrets(std::span<const uint8_t> data)
{
    if (data.empty()) {
        return util::Error{Untranslated("Empty individual secrets data")};
    }

    uint8_t count = data[0];
    if (count == 0) {
        return util::Error{Untranslated("At least one individual secret is required")};
    }

    size_t expected_size = 1 + count * 32;
    if (data.size() < expected_size) {
        return util::Error{Untranslated("Truncated individual secrets data")};
    }

    std::vector<uint256> result;
    result.reserve(count);

    for (size_t i = 0; i < count; ++i) {
        uint256 secret;
        std::memcpy(secret.data(), data.data() + 1 + i * 32, 32);
        result.push_back(secret);
    }

    return result;
}

} // namespace wallet

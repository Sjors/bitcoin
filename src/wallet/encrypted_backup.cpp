// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/encrypted_backup.h>

#include <algorithm>
#include <set>
#include <span>

#include <hash.h>
#include <script/descriptor.h>
#include <serialize.h>
#include <streams.h>
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

util::Result<std::vector<uint8_t>> EncodeIndividualSecrets(const std::vector<uint256>& secrets)
{
    if (secrets.empty()) {
        return util::Error{Untranslated("At least one individual secret is required")};
    }
    if (secrets.size() > 255) {
        return util::Error{Untranslated("Too many individual secrets (max 255)")};
    }

    // Sort secrets lexicographically for consistent encoding
    std::vector<uint256> sorted_secrets = secrets;
    std::sort(sorted_secrets.begin(), sorted_secrets.end());

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

util::Result<std::vector<uint8_t>> EncodeContent(const EncryptedBackupContent& content)
{
    std::vector<uint8_t> result;

    switch (content.type) {
    case ContentType::RESERVED:
        return util::Error{Untranslated("Reserved content type cannot be encoded")};

    case ContentType::BIP_NUMBER:
        result.push_back(static_cast<uint8_t>(ContentType::BIP_NUMBER));
        result.push_back((content.bip_number >> 8) & 0xFF);
        result.push_back(content.bip_number & 0xFF);
        break;

    case ContentType::VENDOR_SPECIFIC: {
        result.push_back(static_cast<uint8_t>(ContentType::VENDOR_SPECIFIC));
        DataStream ss;
        WriteCompactSize(ss, content.payload.size());
        result.insert(result.end(), UCharCast(ss.data()), UCharCast(ss.data()) + ss.size());
        result.insert(result.end(), content.payload.begin(), content.payload.end());
        break;
    }
    }

    if (result.empty()) return util::Error{Untranslated("Unknown content type")};
    return result;
}

util::Result<std::pair<std::optional<EncryptedBackupContent>, size_t>> DecodeContent(std::span<const uint8_t> data)
{
    if (data.empty()) {
        return util::Error{Untranslated("Empty content data")};
    }

    SpanReader reader{data};
    size_t initial_size = reader.size();

    try {
        uint8_t type_byte;
        reader >> type_byte;

        if (type_byte == 0x00) {
            return util::Error{Untranslated("Reserved content type 0x00")};
        }

        if (type_byte >= 0x80) {
            return util::Error{Untranslated("Unsupported content type")};
        }

        EncryptedBackupContent content;
        if (type_byte == static_cast<uint8_t>(ContentType::BIP_NUMBER)) {
            content.type = ContentType::BIP_NUMBER;
            uint8_t hi, lo;
            reader >> hi >> lo;
            content.bip_number = (static_cast<uint16_t>(hi) << 8) | lo;
            return std::make_pair(std::optional<EncryptedBackupContent>{std::move(content)}, initial_size - reader.size());
        }

        uint64_t length = ReadCompactSize(reader);
        if (length > reader.size()) {
            return util::Error{Untranslated("Content data exceeds remaining bytes")};
        }

        if (type_byte == static_cast<uint8_t>(ContentType::VENDOR_SPECIFIC)) {
            content.type = ContentType::VENDOR_SPECIFIC;
            content.payload.resize(length);
            reader.read(MakeWritableByteSpan(content.payload));
            return std::make_pair(std::optional<EncryptedBackupContent>{std::move(content)}, initial_size - reader.size());
        } else {
            reader.ignore(length);
        }

        return std::make_pair(std::optional<EncryptedBackupContent>{}, initial_size - reader.size());
    } catch (const std::ios_base::failure& e) {
        return util::Error{Untranslated(strprintf("Failed to decode content: %s", e.what()))};
    }
}

} // namespace wallet

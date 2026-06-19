// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/encrypted_backup.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <map>
#include <set>
#include <span>

#include <crypto/chacha20poly1305.h>
#include <hash.h>
#include <key_io.h>
#include <random.h>
#include <script/descriptor.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <univalue.h>
#include <util/bip32.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/time.h>
#include <wallet/descriptor_info.h>
#include <wallet/imports.h>
#include <wallet/wallet.h>

namespace wallet {

static std::optional<XOnlyPubKey> ToXOnly(const CExtPubKey& ext_pubkey)
{
    if (!ext_pubkey.pubkey.IsFullyValid() || !ext_pubkey.pubkey.IsValidNonHybrid()) {
        return std::nullopt;
    }
    return XOnlyPubKey{ext_pubkey.pubkey};
}

static std::string DescriptorWithoutChecksum(const std::string& descriptor)
{
    return descriptor.substr(0, descriptor.find('#'));
}

static bool ParsesAsDescriptor(const std::string& descriptor)
{
    FlatSigningProvider provider;
    std::string error;
    return !Parse(descriptor, provider, error, /*require_checksum=*/false).empty();
}

static std::optional<std::pair<std::string, bool>> GetDescriptorBranchGroup(const std::string& descriptor)
{
    const std::string descriptor_without_checksum{DescriptorWithoutChecksum(descriptor)};
    std::string receive_group{descriptor_without_checksum};
    util::ReplaceAll(receive_group, "/0/*", "/<0;1>/*");
    const bool has_receive_branch{receive_group != descriptor_without_checksum};

    std::string change_group{descriptor_without_checksum};
    util::ReplaceAll(change_group, "/1/*", "/<0;1>/*");
    const bool has_change_branch{change_group != descriptor_without_checksum};

    if (has_receive_branch == has_change_branch) return std::nullopt;

    std::string group{has_receive_branch ? std::move(receive_group) : std::move(change_group)};
    if (!ParsesAsDescriptor(group)) {
        return std::nullopt;
    }

    return std::make_pair(std::move(group), has_change_branch);
}

static std::optional<std::string> GetReceiveChangeMultipathDescriptor(const std::string& descriptor)
{
    std::string descriptor_without_checksum{DescriptorWithoutChecksum(descriptor)};
    std::string without_multipath{descriptor_without_checksum};
    util::ReplaceAll(without_multipath, "/<0;1>/*", "");
    if (without_multipath == descriptor_without_checksum || !ParsesAsDescriptor(descriptor_without_checksum)) {
        return std::nullopt;
    }
    return descriptor_without_checksum;
}

static std::string EncryptionAlgorithmString(EncryptionAlgorithm algorithm)
{
    switch (algorithm) {
    case EncryptionAlgorithm::CHACHA20_POLY1305:
        return "ChaCha20-Poly1305";
    case EncryptionAlgorithm::RESERVED:
        break;
    }
    return "unknown";
}

static std::optional<DerivationPath> ExtractTargetDerivationPath(std::string_view descriptor, std::string_view target_xpub)
{
    const size_t xpub_pos{descriptor.find(target_xpub)};
    if (xpub_pos == std::string_view::npos) return std::nullopt;

    if (xpub_pos == 0 || descriptor[xpub_pos - 1] != ']') return std::nullopt;

    const size_t bracket_start{descriptor.rfind('[', xpub_pos - 1)};
    if (bracket_start == std::string_view::npos) return std::nullopt;

    const std::string_view origin{descriptor.substr(bracket_start + 1, xpub_pos - bracket_start - 2)};
    const size_t slash_pos{origin.find('/')};
    if (slash_pos == std::string_view::npos) return std::nullopt;

    DerivationPath parsed_path;
    if (!ParseHDKeypath("m" + std::string{origin.substr(slash_pos)}, parsed_path) || parsed_path.empty()) {
        return std::nullopt;
    }

    return parsed_path;
}

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

util::Result<EncryptedBackup> CreateEncryptedBackup(
    const std::string& descriptor,
    std::span<const uint8_t> plaintext,
    const EncryptedBackupContent& content,
    const std::vector<DerivationPath>& derivation_paths)
{
    if (plaintext.empty()) {
        return util::Error{Untranslated("Plaintext cannot be empty")};
    }

    // Extract keys from descriptor
    auto keys_result = ExtractKeysFromDescriptor(descriptor);
    if (!keys_result) {
        return util::Error{util::ErrorString(keys_result)};
    }
    const std::vector<XOnlyPubKey>& keys = *keys_result;

    // Compute secrets
    uint256 decryption_secret = ComputeDecryptionSecret(keys);
    std::vector<uint256> individual_secrets = ComputeAllIndividualSecrets(decryption_secret, keys);

    auto content_encoded = EncodeContent(content);
    if (!content_encoded) {
        return util::Error{util::ErrorString(content_encoded)};
    }

    std::vector<uint8_t> payload{content_encoded->begin(), content_encoded->end()};
    DataStream plaintext_size;
    WriteCompactSize(plaintext_size, plaintext.size());
    payload.insert(payload.end(), UCharCast(plaintext_size.data()), UCharCast(plaintext_size.data()) + plaintext_size.size());
    payload.insert(payload.end(), plaintext.begin(), plaintext.end());

    std::array<uint8_t, ENCRYPTED_BACKUP_NONCE_SIZE> nonce;
    do {
        GetStrongRandBytes(nonce);
    } while (std::all_of(nonce.begin(), nonce.end(), [](uint8_t byte) { return byte == 0; }));

    AEADChaCha20Poly1305::Nonce96 nonce96;
    SpanReader{std::span{nonce}} >> nonce96.first >> nonce96.second;

    AEADChaCha20Poly1305 aead{MakeByteSpan(decryption_secret)};
    std::vector<uint8_t> ciphertext(payload.size() + AEADChaCha20Poly1305::EXPANSION);
    aead.Encrypt(MakeByteSpan(payload), {}, nonce96, MakeWritableByteSpan(ciphertext));

    // Build result
    EncryptedBackup backup;
    backup.version = ENCRYPTED_BACKUP_VERSION;
    backup.derivation_paths = derivation_paths;
    backup.individual_secrets = std::move(individual_secrets);
    backup.encryption = EncryptionAlgorithm::CHACHA20_POLY1305;
    backup.nonce = nonce;
    backup.ciphertext = std::move(ciphertext);

    return backup;
}

std::vector<uint8_t> EncodeEncryptedBackup(const EncryptedBackup& backup)
{
    std::vector<uint8_t> result;

    // MAGIC (6 bytes)
    result.insert(result.end(), ENCRYPTED_BACKUP_MAGIC.begin(), ENCRYPTED_BACKUP_MAGIC.end());

    // VERSION (1 byte)
    result.push_back(backup.version);

    // DERIVATION_PATHS
    auto paths_encoded = EncodeDerivationPaths(backup.derivation_paths);
    if (paths_encoded) {
        result.insert(result.end(), paths_encoded->begin(), paths_encoded->end());
    } else {
        // Empty paths on error
        result.push_back(0);
    }

    // INDIVIDUAL_SECRETS
    auto secrets_encoded = EncodeIndividualSecrets(backup.individual_secrets);
    if (secrets_encoded) {
        result.insert(result.end(), secrets_encoded->begin(), secrets_encoded->end());
    }

    // ENCRYPTION (1 byte)
    result.push_back(static_cast<uint8_t>(backup.encryption));

    // ENCRYPTED_PAYLOAD: NONCE || LENGTH || CIPHERTEXT
    result.insert(result.end(), backup.nonce.begin(), backup.nonce.end());

    // CompactSize encoding for ciphertext length
    {
        DataStream ss;
        WriteCompactSize(ss, backup.ciphertext.size());
        result.insert(result.end(), UCharCast(ss.data()), UCharCast(ss.data()) + ss.size());
    }

    result.insert(result.end(), backup.ciphertext.begin(), backup.ciphertext.end());

    return result;
}

std::string EncodeEncryptedBackupBase64(const EncryptedBackup& backup)
{
    std::vector<uint8_t> binary = EncodeEncryptedBackup(backup);
    return EncodeBase64(binary);
}

util::Result<EncryptedBackup> DecodeEncryptedBackup(std::span<const uint8_t> data)
{
    if (data.size() < 6 + 1 + 1 + 1 + 1 + 12 + 1) {
        return util::Error{Untranslated("Data too short for encrypted backup")};
    }

    size_t pos = 0;
    EncryptedBackup backup;

    // Check MAGIC
    if (!std::equal(ENCRYPTED_BACKUP_MAGIC.begin(), ENCRYPTED_BACKUP_MAGIC.end(), data.begin())) {
        return util::Error{Untranslated("Invalid magic bytes")};
    }
    pos += 6;

    // VERSION
    backup.version = data[pos++];
    if (backup.version != ENCRYPTED_BACKUP_VERSION) {
        return util::Error{Untranslated(strprintf("Unsupported version: %d", backup.version))};
    }

    // DERIVATION_PATHS
    auto paths_result = DecodeDerivationPaths(data.subspan(pos));
    if (!paths_result) {
        return util::Error{util::ErrorString(paths_result)};
    }
    backup.derivation_paths = *paths_result;

    // Calculate consumed bytes for derivation paths
    size_t paths_size = 1; // count byte
    for (const auto& path : backup.derivation_paths) {
        paths_size += 1 + path.size() * 4; // child_count + children
    }
    pos += paths_size;

    // INDIVIDUAL_SECRETS
    if (pos >= data.size()) {
        return util::Error{Untranslated("Missing individual secrets")};
    }
    auto secrets_result = DecodeIndividualSecrets(data.subspan(pos));
    if (!secrets_result) {
        return util::Error{util::ErrorString(secrets_result)};
    }
    backup.individual_secrets = *secrets_result;
    pos += 1 + backup.individual_secrets.size() * 32;

    // ENCRYPTION
    if (pos >= data.size()) {
        return util::Error{Untranslated("Missing encryption algorithm")};
    }
    uint8_t enc_byte = data[pos++];
    if (enc_byte != static_cast<uint8_t>(EncryptionAlgorithm::CHACHA20_POLY1305)) {
        return util::Error{Untranslated("Unsupported encryption algorithm")};
    }
    backup.encryption = EncryptionAlgorithm::CHACHA20_POLY1305;

    // NONCE
    if (pos + ENCRYPTED_BACKUP_NONCE_SIZE > data.size()) {
        return util::Error{Untranslated("Missing nonce")};
    }
    std::memcpy(backup.nonce.data(), data.data() + pos, ENCRYPTED_BACKUP_NONCE_SIZE);
    if (std::all_of(backup.nonce.begin(), backup.nonce.end(), [](uint8_t byte) { return byte == 0; })) {
        return util::Error{Untranslated("Invalid all-zero nonce")};
    }
    pos += ENCRYPTED_BACKUP_NONCE_SIZE;

    // LENGTH (CompactSize) and CIPHERTEXT
    try {
        SpanReader reader{data.subspan(pos)};
        uint64_t cipher_len = ReadCompactSize(reader);
        if (cipher_len > reader.size()) {
            return util::Error{Untranslated("Truncated ciphertext")};
        }
        backup.ciphertext.resize(cipher_len);
        reader.read(MakeWritableByteSpan(backup.ciphertext));
    } catch (const std::ios_base::failure& e) {
        return util::Error{Untranslated(strprintf("Invalid ciphertext length: %s", e.what()))};
    }

    return backup;
}

util::Result<EncryptedBackup> DecodeEncryptedBackupBase64(const std::string& base64_str)
{
    auto decoded = DecodeBase64(base64_str);
    if (!decoded) {
        return util::Error{Untranslated("Invalid base64 encoding")};
    }
    return DecodeEncryptedBackup(*decoded);
}

static std::optional<std::vector<std::vector<uint8_t>>> FindPlaintextsForContent(std::span<const uint8_t> payload, std::optional<uint16_t> bip_number)
{
    std::vector<std::vector<uint8_t>> plaintexts;
    size_t pos{0};

    while (pos < payload.size()) {
        auto content_result = DecodeContent(payload.subspan(pos));
        if (!content_result) return std::nullopt;

        const auto& content{content_result->first};
        pos += content_result->second;

        SpanReader reader{payload.subspan(pos)};
        uint64_t plaintext_size;
        size_t plaintext_size_len;
        try {
            const size_t initial_size{reader.size()};
            plaintext_size = ReadCompactSize(reader);
            plaintext_size_len = initial_size - reader.size();
        } catch (const std::ios_base::failure&) {
            return std::nullopt;
        }

        pos += plaintext_size_len;
        if (plaintext_size > payload.size() - pos) {
            return std::nullopt;
        }

        if (content && (!bip_number || (content->type == ContentType::BIP_NUMBER && content->bip_number == *bip_number))) {
            plaintexts.emplace_back(payload.begin() + pos, payload.begin() + pos + plaintext_size);
        }
        pos += plaintext_size;
    }

    if (plaintexts.empty()) return std::nullopt;
    return plaintexts;
}

static std::optional<std::vector<std::vector<uint8_t>>> DecryptBackupContentsWithKey(const EncryptedBackup& backup,
                                                                                     const XOnlyPubKey& key,
                                                                                     std::optional<uint16_t> bip_number)
{
    if (backup.ciphertext.size() < AEADChaCha20Poly1305::EXPANSION) {
        return std::nullopt;
    }

    // Compute individual secret for this key
    uint256 si = ComputeIndividualSecret(key);

    AEADChaCha20Poly1305::Nonce96 nonce96;
    SpanReader{std::span{backup.nonce}} >> nonce96.first >> nonce96.second;

    // Try each individual secret in the backup
    for (const auto& ci : backup.individual_secrets) {
        // Reconstruct decryption secret: s = ci XOR si
        uint256 reconstructed_secret;
        for (size_t i = 0; i < 32; ++i) {
            reconstructed_secret.data()[i] = ci.data()[i] ^ si.data()[i];
        }

        AEADChaCha20Poly1305 aead{MakeByteSpan(reconstructed_secret)};
        std::vector<uint8_t> result(backup.ciphertext.size() - AEADChaCha20Poly1305::EXPANSION);
        if (aead.Decrypt(MakeByteSpan(backup.ciphertext), {}, nonce96, MakeWritableByteSpan(result))) {
            return FindPlaintextsForContent(result, bip_number);
        }
    }

    return std::nullopt;
}

std::optional<std::vector<uint8_t>> DecryptBackupWithKey(const EncryptedBackup& backup,
                                                          const XOnlyPubKey& key)
{
    auto plaintexts{DecryptBackupContentsWithKey(backup, key, std::nullopt)};
    if (!plaintexts) return std::nullopt;
    return plaintexts->front();
}

std::optional<std::vector<std::vector<uint8_t>>> DecryptBackupContentsWithKey(const EncryptedBackup& backup,
                                                                               const XOnlyPubKey& key)
{
    return DecryptBackupContentsWithKey(backup, key, std::nullopt);
}

util::Result<std::vector<uint8_t>> DecryptBackupWithDescriptor(const EncryptedBackup& backup,
                                                                const std::string& descriptor)
{
    auto keys_result = ExtractKeysFromDescriptor(descriptor);
    if (!keys_result) {
        return util::Error{util::ErrorString(keys_result)};
    }

    for (const auto& key : *keys_result) {
        auto plaintexts = DecryptBackupContentsWithKey(backup, key, BIP_DESCRIPTORS);
        if (plaintexts) {
            return plaintexts->front();
        }
    }

    return util::Error{Untranslated("No matching key found for decryption")};
}

struct DescriptorBackupSet {
    std::optional<WalletDescriptorInfo> receive;
    std::optional<WalletDescriptorInfo> change;
    std::string multipath_descriptor;
    bool multipath{false};
    bool archived{true};
    std::optional<std::pair<int64_t, int64_t>> range;
    uint64_t birth_time{std::numeric_limits<uint64_t>::max()};
};

static util::Result<void> AddDescriptorToBackupSet(DescriptorBackupSet& set, WalletDescriptorInfo info, bool change, bool multipath = false)
{
    if (set.range && info.range) {
        set.range = std::make_pair(
            std::min(set.range->first, info.range->first),
            std::max(set.range->second, info.range->second));
    } else if (!set.range) {
        set.range = info.range;
    }
    set.birth_time = std::min(set.birth_time, info.creation_time);
    set.archived = set.archived && !info.active;
    set.multipath = set.multipath || multipath;

    auto& target{change ? set.change : set.receive};
    if (target) {
        return util::Error{Untranslated("Duplicate receive or change descriptor in backup set.")};
    }
    target = std::move(info);
    return {};
}

static std::string DescriptorBackupSetMultipathDescriptor(const DescriptorBackupSet& set)
{
    return set.multipath_descriptor;
}

static UniValue DescriptorBackupSetToUniValue(const DescriptorBackupSet& set)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("descriptor", set.receive->descriptor);
    if (set.change) {
        obj.pushKV("change_descriptor", set.change->descriptor);
    }
    if (set.archived) {
        obj.pushKV("archived", true);
    }
    if (set.birth_time != std::numeric_limits<uint64_t>::max()) {
        obj.pushKV("birth_time", set.birth_time);
    }
    if (set.range) {
        UniValue range(UniValue::VARR);
        range.push_back(set.range->first);
        // range_end is exclusive internally, display as inclusive (hence -1)
        range.push_back(set.range->second - 1);
        obj.pushKV("range", std::move(range));
    }
    return obj;
}

static util::Result<std::optional<std::pair<int64_t, int64_t>>> ParseDescriptorBackupRange(const UniValue& range)
{
    if (range.isNull()) return std::optional<std::pair<int64_t, int64_t>>{};
    if (!range.isArray() || range.size() != 2) {
        return util::Error{Untranslated("Descriptor backup range must contain two indexes.")};
    }

    const int64_t begin{range[0].getInt<int64_t>()};
    const int64_t end_inclusive{range[1].getInt<int64_t>()};
    if (begin < 0 || end_inclusive < begin || end_inclusive == std::numeric_limits<int64_t>::max()) {
        return util::Error{Untranslated("Descriptor backup range is invalid.")};
    }
    return std::optional{std::make_pair(begin, end_inclusive)};
}

static std::string DescriptorWithChecksum(const std::string& descriptor)
{
    if (descriptor.find('#') != std::string::npos) return descriptor;
    return descriptor + "#" + GetDescriptorChecksum(descriptor);
}

static util::Result<std::vector<ImportDescriptorRequest>> ParseDescriptorBackupImports(std::string_view content)
{
    const int64_t now{GetTime()};
    std::vector<ImportDescriptorRequest> imports;

    if (util::TrimStringView(content).starts_with("{")) {
        UniValue descriptor_backup;
        if (!descriptor_backup.read(content) || !descriptor_backup.isObject()) {
            return util::Error{Untranslated("Failed to parse descriptor backup JSON.")};
        }
        if (!descriptor_backup.exists("descriptor_sets") || !descriptor_backup["descriptor_sets"].isArray()) {
            return util::Error{Untranslated("Descriptor backup JSON is missing descriptor_sets.")};
        }

        for (const UniValue& descriptor_set : descriptor_backup["descriptor_sets"].getValues()) {
            if (!descriptor_set.isObject() || !descriptor_set.exists("descriptor") || !descriptor_set["descriptor"].isStr()) {
                return util::Error{Untranslated("Descriptor backup set is missing a descriptor.")};
            }
            const std::string descriptor{descriptor_set["descriptor"].get_str()};

            auto range{ParseDescriptorBackupRange(descriptor_set["range"])};
            if (!range) return util::Error{util::ErrorString(range)};

            const bool active{!descriptor_set.exists("archived") || !descriptor_set["archived"].get_bool()};
            const int64_t timestamp{descriptor_set.exists("birth_time") ? descriptor_set["birth_time"].getInt<int64_t>() : now};
            imports.push_back({
                .descriptor = descriptor,
                .label = std::nullopt,
                .timestamp = timestamp,
                .active = active,
                .internal = false,
                .range = *range,
                .next_index = std::nullopt,
            });

            if (descriptor_set.exists("change_descriptor")) {
                if (!descriptor_set["change_descriptor"].isStr()) {
                    return util::Error{Untranslated("Descriptor backup change_descriptor must be a string.")};
                }
                if (descriptor.find("/<") != std::string::npos) {
                    return util::Error{Untranslated("Descriptor backup must not include a change_descriptor for a multipath descriptor.")};
                }
                imports.push_back({
                    .descriptor = descriptor_set["change_descriptor"].get_str(),
                    .label = std::nullopt,
                    .timestamp = timestamp,
                    .active = active,
                    .internal = true,
                    .range = *range,
                    .next_index = std::nullopt,
                });
            }
        }
    } else {
        for (const auto& untrimmed_line : util::SplitString(content, '\n')) {
            const std::string line{util::TrimString(untrimmed_line)};
            if (line.empty() || line.starts_with("#")) continue;
            imports.push_back({
                .descriptor = DescriptorWithChecksum(line),
                .label = std::nullopt,
                .timestamp = now,
                .active = true,
                .internal = std::nullopt,
                .range = std::nullopt,
                .next_index = std::nullopt,
            });
        }
    }

    if (imports.empty()) {
        return util::Error{Untranslated("Descriptor backup did not contain any descriptors.")};
    }
    return imports;
}

static util::Result<void> PreserveExistingDescriptorRange(CWallet& wallet, ImportDescriptorRequest& request) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    FlatSigningProvider keys;
    std::string error;
    auto parsed_descs{Parse(request.descriptor, keys, error, /*require_checksum=*/true)};
    if (parsed_descs.empty()) {
        return util::Error{Untranslated(strprintf("Unable to parse descriptor '%s': %s", request.descriptor, error))};
    }

    for (auto& parsed_desc : parsed_descs) {
        WalletDescriptor wallet_descriptor(std::move(parsed_desc), /*creation_time=*/0, /*range_start=*/0, /*range_end=*/1, /*next_index=*/0);
        if (!wallet_descriptor.descriptor->IsRange()) continue;
        if (auto existing_spk_manager{wallet.GetDescriptorScriptPubKeyMan(wallet_descriptor)}) {
            LOCK(existing_spk_manager->cs_desc_man);
            const WalletDescriptor existing_descriptor{existing_spk_manager->GetWalletDescriptor()};
            const auto existing_range{std::make_pair<int64_t, int64_t>(existing_descriptor.range_start, existing_descriptor.range_end - 1)};
            if (request.range) {
                request.range = std::make_pair(std::min(request.range->first, existing_range.first), std::max(request.range->second, existing_range.second));
            } else {
                request.range = existing_range;
            }
            request.next_index = existing_descriptor.next_index;
        }
    }

    return {};
}

util::Result<std::string> CWallet::CreateEncryptedDescriptorBackup(const std::optional<std::string>& target_xpub, bool compact) const
{
    if (target_xpub) {
        const CExtPubKey ext_pubkey{DecodeExtPubKey(*target_xpub)};
        if (!ext_pubkey.pubkey.IsValid()) {
            return util::Error{Untranslated(strprintf("Invalid extended public key: %s", *target_xpub))};
        }
    }

    std::vector<WalletDescriptorInfo> all_descriptors;
    std::vector<DerivationPath> derivation_paths;
    bool found_target_xpub{false};

    {
        LOCK(cs_wallet);

        const auto active_spk_mans{GetActiveScriptPubKeyMans()};

        for (const auto& spk_man : GetAllScriptPubKeyMans()) {
            auto desc_spk_man{dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man)};
            if (!desc_spk_man) continue;

            LOCK(desc_spk_man->cs_desc_man);
            std::string desc_str;
            if (!desc_spk_man->GetDescriptorString(desc_str, /*priv=*/false)) {
                return util::Error{Untranslated("Failed to get descriptor string.")};
            }

            const auto& wallet_desc{desc_spk_man->GetWalletDescriptor()};
            const bool is_range{wallet_desc.descriptor->IsRange()};
            WalletDescriptorInfo info{
                desc_str,
                wallet_desc.creation_time,
                active_spk_mans.contains(desc_spk_man),
                IsInternalScriptPubKeyMan(desc_spk_man),
                is_range ? std::optional(std::make_pair(wallet_desc.range_start, wallet_desc.range_end)) : std::nullopt,
                wallet_desc.next_index
            };
            all_descriptors.push_back(std::move(info));

            if (target_xpub && desc_str.find(*target_xpub) != std::string::npos) {
                found_target_xpub = true;
                if (derivation_paths.empty()) {
                    if (auto path{ExtractTargetDerivationPath(desc_str, *target_xpub)}) {
                        derivation_paths.push_back(*path);
                    }
                }
            }
        }
    }

    if (all_descriptors.empty()) {
        return util::Error{Untranslated("No descriptors found in wallet.")};
    }

    if (target_xpub && !found_target_xpub) {
        return util::Error{Untranslated(strprintf("Specified xpub not found in any wallet descriptor: %s", *target_xpub))};
    }

    if (target_xpub && derivation_paths.empty()) {
        return util::Error{Untranslated("Specified xpub has no origin info (derivation path) in descriptor.")};
    }

    std::map<std::string, DescriptorBackupSet> descriptor_sets;
    for (const auto& info : all_descriptors) {
        if (auto multipath_descriptor{GetReceiveChangeMultipathDescriptor(info.descriptor)}) {
            auto& descriptor_set{descriptor_sets[*multipath_descriptor]};
            descriptor_set.multipath_descriptor = *multipath_descriptor;
            auto add_result{AddDescriptorToBackupSet(descriptor_set, info, /*change=*/false, /*multipath=*/true)};
            if (!add_result) {
                return util::Error{util::ErrorString(add_result)};
            }
            continue;
        }

        const auto branch_group{GetDescriptorBranchGroup(info.descriptor)};
        if (!branch_group) {
            return util::Error{Untranslated(strprintf("Descriptor is not a receive/change pair and cannot be backed up as BIP380 content: %s", info.descriptor))};
        }

        auto& descriptor_set{descriptor_sets[branch_group->first]};
        descriptor_set.multipath_descriptor = branch_group->first;
        auto add_result{AddDescriptorToBackupSet(descriptor_set, info, branch_group->second)};
        if (!add_result) {
            return util::Error{util::ErrorString(add_result)};
        }
    }

    std::vector<DescriptorBackupSet> sorted_sets;
    sorted_sets.reserve(descriptor_sets.size());
    for (auto& [_, set] : descriptor_sets) {
        if (!set.receive || (!set.multipath && !set.change)) {
            return util::Error{Untranslated("Descriptor backup requires both receive and change descriptors.")};
        }
        if (set.multipath && set.change) {
            return util::Error{Untranslated("Multipath descriptor backup must not include a change descriptor.")};
        }
        sorted_sets.push_back(std::move(set));
    }

    std::sort(sorted_sets.begin(), sorted_sets.end(), [](const auto& a, const auto& b) {
        return a.receive->descriptor < b.receive->descriptor;
    });

    const std::string primary_descriptor{sorted_sets.front().receive->descriptor};
    std::string plaintext_str;
    if (compact) {
        for (const auto& descriptor_set : sorted_sets) {
            if (!plaintext_str.empty()) plaintext_str += '\n';
            plaintext_str += DescriptorBackupSetMultipathDescriptor(descriptor_set);
        }
        plaintext_str += '\n';
    } else {
        UniValue descriptor_sets_arr(UniValue::VARR);
        for (const auto& descriptor_set : sorted_sets) {
            descriptor_sets_arr.push_back(DescriptorBackupSetToUniValue(descriptor_set));
        }

        UniValue descriptor_backup(UniValue::VOBJ);
        descriptor_backup.pushKV("version", 1);
        descriptor_backup.pushKV("descriptor_sets", std::move(descriptor_sets_arr));
        plaintext_str = descriptor_backup.write();
    }

    const std::vector<uint8_t> plaintext{plaintext_str.begin(), plaintext_str.end()};
    const EncryptedBackupContent content{
        .type = ContentType::BIP_NUMBER,
        .bip_number = BIP_DESCRIPTORS,
        .payload = {},
    };

    auto backup_result{CreateEncryptedBackup(primary_descriptor, plaintext, content, derivation_paths)};
    if (!backup_result) {
        return util::Error{Untranslated(strprintf("Failed to create encrypted backup: %s", util::ErrorString(backup_result).original))};
    }

    return EncodeEncryptedBackupBase64(*backup_result);
}

util::Result<std::vector<uint8_t>> CWallet::DecryptEncryptedBackupBase64WithExtPubKey(const std::string& base64_str, const std::string& pubkey_str)
{
    const CExtPubKey ext_pubkey{DecodeExtPubKey(pubkey_str)};
    if (!ext_pubkey.pubkey.IsValid()) {
        return util::Error{Untranslated(strprintf("Invalid extended public key: %s", pubkey_str))};
    }

    auto backup_result{DecodeEncryptedBackupBase64(base64_str)};
    if (!backup_result) {
        return util::Error{Untranslated(strprintf("Failed to decode backup: %s", util::ErrorString(backup_result).original))};
    }

    auto xonly_key{ToXOnly(ext_pubkey)};
    if (!xonly_key) {
        return util::Error{Untranslated(strprintf("Invalid extended public key: %s", pubkey_str))};
    }

    auto plaintexts{DecryptBackupContentsWithKey(*backup_result, *xonly_key, BIP_DESCRIPTORS)};
    if (!plaintexts) {
        return util::Error{Untranslated("Failed to decrypt backup: provided key does not match any recipient.")};
    }

    return plaintexts->front();
}

util::Result<int> CWallet::ImportEncryptedDescriptorBackup(const std::string& base64_str, const std::string& pubkey_str)
{
    auto decrypted{DecryptEncryptedBackupBase64WithExtPubKey(base64_str, pubkey_str)};
    if (!decrypted) {
        return util::Error{util::ErrorString(decrypted)};
    }

    const std::string content{decrypted->begin(), decrypted->end()};
    auto imports{ParseDescriptorBackupImports(content)};
    if (!imports) {
        return util::Error{util::ErrorString(imports)};
    }

    int imported{0};
    {
        LOCK(cs_wallet);
        for (auto& import : *imports) {
            auto range_result{PreserveExistingDescriptorRange(*this, import)};
            if (!range_result) {
                return util::Error{util::ErrorString(range_result)};
            }

            auto import_result{wallet::ImportDescriptor(*this, import)};
            if (import_result.result_code != wallet::ImportDescriptorResult::ImportResultCode::OK) {
                return util::Error{Untranslated(import_result.error_message)};
            }
            ++imported;
        }
        ConnectScriptPubKeyManNotifiers();
        RefreshAllTXOs();
    }

    return imported;
}

util::Result<EncryptedBackupMetadata> CWallet::GetEncryptedBackupMetadata(const std::string& base64_str)
{
    auto backup_result{DecodeEncryptedBackupBase64(base64_str)};
    if (!backup_result) {
        return util::Error{Untranslated(strprintf("Failed to decode backup: %s", util::ErrorString(backup_result).original))};
    }

    return EncryptedBackupMetadata{
        .version = backup_result->version,
        .recipient_count = backup_result->individual_secrets.size(),
        .encryption = EncryptionAlgorithmString(backup_result->encryption),
        .derivation_paths = backup_result->derivation_paths,
    };
}

} // namespace wallet

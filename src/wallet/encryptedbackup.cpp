// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/encryptedbackup.h>

#include <cstring>

#include <crypto/chacha20poly1305.h>
#include <hash.h>
#include <key_io.h>
#include <random.h>
#include <script/descriptor.h>
#include <serialize.h>
#include <streams.h>
#include <util/bip32.h>
#include <util/strencodings.h>

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

util::Result<DerivationPath> ParseDerivationPath(const std::string& path_str)
{
    // Require "m" prefix for BIP-xxxx paths
    if (path_str.empty() || path_str[0] != 'm') {
        return util::Error{Untranslated("Derivation path must start with 'm'")};
    }

    DerivationPath result;
    if (!ParseHDKeypath(path_str, result)) {
        return util::Error{Untranslated(strprintf("Invalid derivation path: %s", path_str))};
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

    for (const auto& path : paths) {
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
        // BIP number is big-endian uint16, no LENGTH field
        result.push_back((content.bip_number >> 8) & 0xFF);
        result.push_back(content.bip_number & 0xFF);
        break;

    case ContentType::VENDOR_SPECIFIC: {
        result.push_back(static_cast<uint8_t>(ContentType::VENDOR_SPECIFIC));
        // CompactSize encoding for length
        DataStream ss;
        WriteCompactSize(ss, content.vendor_data.size());
        result.insert(result.end(), UCharCast(ss.data()), UCharCast(ss.data()) + ss.size());
        result.insert(result.end(), content.vendor_data.begin(), content.vendor_data.end());
        break;
    }

    default:
        return util::Error{Untranslated("Unknown content type")};
    }

    return result;
}

util::Result<std::pair<EncryptedBackupContent, size_t>> DecodeContent(std::span<const uint8_t> data)
{
    if (data.empty()) {
        return util::Error{Untranslated("Empty content data")};
    }

    EncryptedBackupContent content;
    SpanReader reader{data};
    size_t initial_size = reader.size();

    try {
        uint8_t type_byte;
        reader >> type_byte;

        if (type_byte == 0x00) {
            return util::Error{Untranslated("Reserved content type 0x00")};
        }

        if (type_byte >= 0x80) {
            return util::Error{Untranslated("Content type >= 0x80 stops parsing")};
        }

        if (type_byte == static_cast<uint8_t>(ContentType::BIP_NUMBER)) {
            content.type = ContentType::BIP_NUMBER;
            // BIP number is big-endian uint16, read manually
            uint8_t hi, lo;
            reader >> hi >> lo;
            content.bip_number = (static_cast<uint16_t>(hi) << 8) | lo;
        } else if (type_byte == static_cast<uint8_t>(ContentType::VENDOR_SPECIFIC)) {
            content.type = ContentType::VENDOR_SPECIFIC;
            uint64_t length = ReadCompactSize(reader);
            if (length > reader.size()) {
                return util::Error{Untranslated("Vendor data exceeds remaining bytes")};
            }
            content.vendor_data.resize(length);
            reader.read(MakeWritableByteSpan(content.vendor_data));
        } else {
            // Unknown type < 0x80: skip by reading length
            content.type = static_cast<ContentType>(type_byte);
            uint64_t length = ReadCompactSize(reader);
            if (length > reader.size()) {
                return util::Error{Untranslated("Content data exceeds remaining bytes")};
            }
            reader.ignore(length);
        }

        return std::make_pair(content, initial_size - reader.size());
    } catch (const std::ios_base::failure& e) {
        return util::Error{Untranslated(strprintf("Failed to decode content: %s", e.what()))};
    }
}

std::vector<uint8_t> EncryptChaCha20Poly1305(std::span<const uint8_t> plaintext,
                                              const uint256& secret,
                                              std::span<const uint8_t, ENCRYPTED_BACKUP_NONCE_SIZE> nonce)
{
    // Convert secret to byte span
    std::array<std::byte, 32> key_bytes;
    std::memcpy(key_bytes.data(), secret.data(), 32);

    // Initialize AEAD
    AEADChaCha20Poly1305 aead{key_bytes};

    // Prepare nonce (96-bit = 12 bytes)
    std::array<std::byte, AEADChaCha20Poly1305::NONCE_SIZE> nonce_bytes;
    std::memcpy(nonce_bytes.data(), nonce.data(), nonce.size());
    auto nonce96 = AEADChaCha20Poly1305::NonceFromBytes(nonce_bytes);

    // Convert plaintext to byte span
    std::vector<std::byte> plain_bytes(plaintext.size());
    std::memcpy(plain_bytes.data(), plaintext.data(), plaintext.size());

    // Allocate output (plaintext + 16-byte tag)
    std::vector<std::byte> cipher_bytes(plaintext.size() + AEADChaCha20Poly1305::EXPANSION);

    // Encrypt with empty AAD
    aead.Encrypt(plain_bytes, {}, nonce96, cipher_bytes);

    // Convert back to uint8_t
    std::vector<uint8_t> result(cipher_bytes.size());
    std::memcpy(result.data(), cipher_bytes.data(), cipher_bytes.size());

    return result;
}

std::optional<std::vector<uint8_t>> DecryptChaCha20Poly1305(std::span<const uint8_t> ciphertext,
                                                             const uint256& secret,
                                                             std::span<const uint8_t, ENCRYPTED_BACKUP_NONCE_SIZE> nonce)
{
    if (ciphertext.size() < AEADChaCha20Poly1305::EXPANSION) {
        return std::nullopt;
    }

    // Convert secret to byte span
    std::array<std::byte, 32> key_bytes;
    std::memcpy(key_bytes.data(), secret.data(), 32);

    // Initialize AEAD
    AEADChaCha20Poly1305 aead{key_bytes};

    // Prepare nonce
    std::array<std::byte, AEADChaCha20Poly1305::NONCE_SIZE> nonce_bytes;
    std::memcpy(nonce_bytes.data(), nonce.data(), nonce.size());
    auto nonce96 = AEADChaCha20Poly1305::NonceFromBytes(nonce_bytes);

    // Convert ciphertext to byte span
    std::vector<std::byte> cipher_bytes(ciphertext.size());
    std::memcpy(cipher_bytes.data(), ciphertext.data(), ciphertext.size());

    // Allocate output
    std::vector<std::byte> plain_bytes(ciphertext.size() - AEADChaCha20Poly1305::EXPANSION);

    // Decrypt with empty AAD
    if (!aead.Decrypt(cipher_bytes, {}, nonce96, plain_bytes)) {
        return std::nullopt;
    }

    // Convert back to uint8_t
    std::vector<uint8_t> result(plain_bytes.size());
    std::memcpy(result.data(), plain_bytes.data(), plain_bytes.size());

    return result;
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
    const std::vector<uint256>& keys = *keys_result;

    // Compute secrets
    uint256 decryption_secret = ComputeDecryptionSecret(keys);
    std::vector<uint256> individual_secrets = ComputeAllIndividualSecrets(decryption_secret, keys);

    // Encode content prefix
    auto content_encoded = EncodeContent(content);
    if (!content_encoded) {
        return util::Error{util::ErrorString(content_encoded)};
    }

    // Build payload: CONTENT || PLAINTEXT
    std::vector<uint8_t> payload;
    payload.insert(payload.end(), content_encoded->begin(), content_encoded->end());
    payload.insert(payload.end(), plaintext.begin(), plaintext.end());

    // Generate random nonce
    std::array<uint8_t, ENCRYPTED_BACKUP_NONCE_SIZE> nonce;
    GetStrongRandBytes(nonce);

    // Encrypt
    std::vector<uint8_t> ciphertext = EncryptChaCha20Poly1305(payload, decryption_secret, nonce);

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

std::optional<std::vector<uint8_t>> DecryptBackupWithKey(const EncryptedBackup& backup,
                                                          const uint256& key)
{
    // Compute individual secret for this key
    uint256 si = ComputeIndividualSecret(key);

    // Try each individual secret in the backup
    for (const auto& ci : backup.individual_secrets) {
        // Reconstruct decryption secret: s = ci XOR si
        uint256 reconstructed_secret;
        for (size_t i = 0; i < 32; ++i) {
            reconstructed_secret.data()[i] = ci.data()[i] ^ si.data()[i];
        }

        // Try to decrypt
        auto result = DecryptChaCha20Poly1305(backup.ciphertext, reconstructed_secret, backup.nonce);
        if (result) {
            // Decryption succeeded - strip the content prefix and return plaintext
            auto content_result = DecodeContent(*result);
            if (content_result) {
                size_t content_size = content_result->second;
                if (content_size <= result->size()) {
                    return std::vector<uint8_t>(result->begin() + content_size, result->end());
                }
            }
            // If content parsing fails, return full payload
            return result;
        }
    }

    return std::nullopt;
}

util::Result<std::vector<uint8_t>> DecryptBackupWithDescriptor(const EncryptedBackup& backup,
                                                                const std::string& descriptor)
{
    auto keys_result = ExtractKeysFromDescriptor(descriptor);
    if (!keys_result) {
        return util::Error{util::ErrorString(keys_result)};
    }

    for (const auto& key : *keys_result) {
        auto result = DecryptBackupWithKey(backup, key);
        if (result) {
            return *result;
        }
    }

    return util::Error{Untranslated("No matching key found for decryption")};
}

} // namespace wallet

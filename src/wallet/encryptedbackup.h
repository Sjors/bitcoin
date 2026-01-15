// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_ENCRYPTEDBACKUP_H
#define BITCOIN_WALLET_ENCRYPTEDBACKUP_H

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <utility>
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

/** Magic bytes for encrypted backup format */
static constexpr std::array<uint8_t, 6> ENCRYPTED_BACKUP_MAGIC = {'B', 'I', 'P', 'X', 'X', 'X'};

/** Current format version */
static constexpr uint8_t ENCRYPTED_BACKUP_VERSION = 0x01;

/** Encryption algorithm identifiers */
enum class EncryptionAlgorithm : uint8_t {
    RESERVED = 0x00,
    CHACHA20_POLY1305 = 0x01,
};

/** Size of the nonce for ChaCha20-Poly1305 */
static constexpr size_t ENCRYPTED_BACKUP_NONCE_SIZE = 12;

/** Size of the authentication tag */
static constexpr size_t ENCRYPTED_BACKUP_TAG_SIZE = 16;

/** Prefix for deriving the decryption secret */
static constexpr std::string_view BIP_DECRYPTION_SECRET_TAG = "BIP_XXXX_DECRYPTION_SECRET";

/** Prefix for deriving individual secrets */
static constexpr std::string_view BIP_INDIVIDUAL_SECRET_TAG = "BIP_XXXX_INDIVIDUAL_SECRET";

/**
 * Represents a parsed derivation path (e.g., m/44'/0'/0').
 * Each element is a 32-bit child index where hardened indices have the high bit set.
 */
using DerivationPath = std::vector<uint32_t>;

/** Content type identifiers */
enum class ContentType : uint8_t {
    RESERVED = 0x00,
    BIP_NUMBER = 0x01,
    VENDOR_SPECIFIC = 0x02,
};

/** Well-known BIP numbers for content types */
static constexpr uint16_t BIP_DESCRIPTORS = 380;
static constexpr uint16_t BIP_WALLET_POLICIES = 388;
static constexpr uint16_t BIP_LABELS = 329;

/**
 * Represents the content metadata in an encrypted backup.
 */
struct EncryptedBackupContent {
    ContentType type{ContentType::RESERVED};
    uint16_t bip_number{0};                    // Used when type == BIP_NUMBER
    std::vector<uint8_t> vendor_data;          // Used when type == VENDOR_SPECIFIC
};

/**
 * Represents a complete encrypted backup structure.
 *
 * This struct represents the parsed/encoded backup format. Note that the content
 * type metadata is stored inside the encrypted payload, not in this struct.
 * The content is passed separately to CreateEncryptedBackup() and decoded
 * separately after decryption.
 */
struct EncryptedBackup {
    uint8_t version{ENCRYPTED_BACKUP_VERSION};
    std::vector<DerivationPath> derivation_paths;
    std::vector<uint256> individual_secrets;
    EncryptionAlgorithm encryption{EncryptionAlgorithm::CHACHA20_POLY1305};
    std::array<uint8_t, ENCRYPTED_BACKUP_NONCE_SIZE> nonce;
    std::vector<uint8_t> ciphertext;  // Includes content prefix and authentication tag
};

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

/**
 * Compute the decryption secret from a set of public keys.
 *
 * s = sha256("BIP_XXXX_DECRYPTION_SECRET" || p1 || p2 || ... || pn)
 * where p1...pn are sorted lexicographically.
 *
 * @param[in] keys The normalized x-only public keys (must be sorted)
 * @return The 32-byte decryption secret
 */
uint256 ComputeDecryptionSecret(const std::vector<uint256>& keys);

/**
 * Compute an individual secret for a specific public key.
 *
 * si = sha256("BIP_XXXX_INDIVIDUAL_SECRET" || pi)
 *
 * @param[in] key The normalized x-only public key
 * @return The 32-byte individual secret
 */
uint256 ComputeIndividualSecret(const uint256& key);

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
                                                  const std::vector<uint256>& keys);

/**
 * Parse a derivation path string (e.g., "m/44'/0'/0'") into a DerivationPath.
 *
 * @param[in] path_str The path string to parse
 * @return The parsed path, or error message
 */
util::Result<DerivationPath> ParseDerivationPath(const std::string& path_str);

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

/**
 * Encode individual secrets according to the backup format.
 *
 * @param[in] secrets Vector of individual secrets
 * @return Encoded bytes, or error if empty or too many secrets
 */
util::Result<std::vector<uint8_t>> EncodeIndividualSecrets(const std::vector<uint256>& secrets);

/**
 * Decode individual secrets from backup format.
 *
 * @param[in] data The encoded data
 * @return Vector of individual secrets, or error message
 */
util::Result<std::vector<uint256>> DecodeIndividualSecrets(std::span<const uint8_t> data);

/**
 * Encode content metadata according to the backup format.
 *
 * @param[in] content The content metadata
 * @return Encoded bytes, or error message
 */
util::Result<std::vector<uint8_t>> EncodeContent(const EncryptedBackupContent& content);

/**
 * Decode content metadata from backup format.
 *
 * @param[in] data The encoded data
 * @return Content metadata and bytes consumed, or error message
 */
util::Result<std::pair<EncryptedBackupContent, size_t>> DecodeContent(std::span<const uint8_t> data);

/**
 * Encrypt plaintext using ChaCha20-Poly1305.
 *
 * @param[in] plaintext The data to encrypt
 * @param[in] secret The 32-byte encryption secret
 * @param[in] nonce The 12-byte nonce
 * @return Ciphertext with authentication tag appended
 */
std::vector<uint8_t> EncryptChaCha20Poly1305(std::span<const uint8_t> plaintext,
                                              const uint256& secret,
                                              std::span<const uint8_t, ENCRYPTED_BACKUP_NONCE_SIZE> nonce);

/**
 * Decrypt ciphertext using ChaCha20-Poly1305.
 *
 * @param[in] ciphertext The encrypted data with authentication tag
 * @param[in] secret The 32-byte decryption secret
 * @param[in] nonce The 12-byte nonce
 * @return Plaintext, or nullopt if authentication fails
 */
std::optional<std::vector<uint8_t>> DecryptChaCha20Poly1305(std::span<const uint8_t> ciphertext,
                                                             const uint256& secret,
                                                             std::span<const uint8_t, ENCRYPTED_BACKUP_NONCE_SIZE> nonce);

/**
 * Create an encrypted backup from a descriptor and plaintext payload.
 *
 * @param[in] descriptor The wallet descriptor (used to derive encryption key)
 * @param[in] plaintext The data to encrypt (typically the descriptor itself or labels)
 * @param[in] content Content type metadata
 * @param[in] derivation_paths Optional derivation paths to include
 * @return The encrypted backup structure, or error message
 */
util::Result<EncryptedBackup> CreateEncryptedBackup(
    const std::string& descriptor,
    std::span<const uint8_t> plaintext,
    const EncryptedBackupContent& content,
    const std::vector<DerivationPath>& derivation_paths = {});

/**
 * Encode an encrypted backup to binary format.
 *
 * @param[in] backup The backup structure to encode
 * @return Encoded binary data
 */
std::vector<uint8_t> EncodeEncryptedBackup(const EncryptedBackup& backup);

/**
 * Encode an encrypted backup to base64 string.
 *
 * @param[in] backup The backup structure to encode
 * @return Base64-encoded string
 */
std::string EncodeEncryptedBackupBase64(const EncryptedBackup& backup);

/**
 * Decode an encrypted backup from binary format.
 *
 * @param[in] data The encoded binary data
 * @return The backup structure, or error message
 */
util::Result<EncryptedBackup> DecodeEncryptedBackup(std::span<const uint8_t> data);

/**
 * Decode an encrypted backup from base64 string.
 *
 * @param[in] base64_str The base64-encoded string
 * @return The backup structure, or error message
 */
util::Result<EncryptedBackup> DecodeEncryptedBackupBase64(const std::string& base64_str);

/**
 * Attempt to decrypt an encrypted backup using a single public key.
 *
 * Tries to reconstruct the decryption secret using the individual secrets
 * in the backup and the provided key.
 *
 * @param[in] backup The encrypted backup
 * @param[in] key The normalized x-only public key to try
 * @return Decrypted plaintext, or nullopt if key doesn't match or decryption fails
 */
std::optional<std::vector<uint8_t>> DecryptBackupWithKey(const EncryptedBackup& backup,
                                                          const uint256& key);

/**
 * Attempt to decrypt an encrypted backup using any matching key from a descriptor.
 *
 * @param[in] backup The encrypted backup
 * @param[in] descriptor A descriptor containing potential decryption keys
 * @return Decrypted plaintext, or error message
 */
util::Result<std::vector<uint8_t>> DecryptBackupWithDescriptor(const EncryptedBackup& backup,
                                                                const std::string& descriptor);

} // namespace wallet

#endif // BITCOIN_WALLET_ENCRYPTEDBACKUP_H

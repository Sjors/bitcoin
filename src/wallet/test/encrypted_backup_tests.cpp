// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/encryptedbackup.h>

#include <test/data/bip_encrypted_backup_content_type.json.h>
#include <test/data/bip_encrypted_backup_derivation_path.json.h>
#include <test/data/bip_encrypted_backup_encryption_secret.json.h>
#include <test/data/bip_encrypted_backup_individual_secrets.json.h>
#include <test/data/bip_encrypted_backup_keys_types.json.h>

#include <base58.h>
#include <key_io.h>
#include <random.h>
#include <test/util/json.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>
#include <univalue.h>

namespace wallet {

// Use RegTest chain type so tpub keys (testnet prefixes) can be parsed
struct EncryptedBackupTestingSetup : public BasicTestingSetup {
    EncryptedBackupTestingSetup() : BasicTestingSetup(ChainType::REGTEST) {}
};

BOOST_FIXTURE_TEST_SUITE(encrypted_backup_tests, EncryptedBackupTestingSetup)

BOOST_AUTO_TEST_CASE(key_normalization_test)
{
    // Test key normalization using BIP test vectors
    UniValue vectors = read_json(json_tests::bip_encrypted_backup_keys_types);

    for (size_t i = 0; i < vectors.size(); ++i) {
        const UniValue& vec = vectors[i];
        std::string description = vec["description"].get_str();
        std::string key_str = vec["key"].get_str();
        std::string expected_hex = vec["expected"].get_str();

        BOOST_TEST_MESSAGE("Testing: " << description);

        // Parse the expected x-only key
        auto expected_bytes = ParseHex(expected_hex);
        BOOST_REQUIRE_EQUAL(expected_bytes.size(), 32u);
        uint256 expected;
        std::memcpy(expected.data(), expected_bytes.data(), 32);

        // Determine key type and normalize
        uint256 result;

        if (key_str.size() == 64) {
            // X-only public key (32 bytes hex = 64 chars)
            auto key_bytes = ParseHex(key_str);
            BOOST_REQUIRE_EQUAL(key_bytes.size(), 32u);
            std::memcpy(result.data(), key_bytes.data(), 32);
        } else if (key_str.size() == 66 && (key_str[0] == '0' && (key_str[1] == '2' || key_str[1] == '3'))) {
            // Compressed public key
            auto key_bytes = ParseHex(key_str);
            BOOST_REQUIRE_EQUAL(key_bytes.size(), 33u);
            CPubKey pubkey(key_bytes.begin(), key_bytes.end());
            result = NormalizeToXOnly(pubkey);
        } else if (key_str.size() == 130 && key_str.starts_with("04")) {
            // Uncompressed public key
            auto key_bytes = ParseHex(key_str);
            BOOST_REQUIRE_EQUAL(key_bytes.size(), 65u);
            CPubKey pubkey(key_bytes.begin(), key_bytes.end());
            result = NormalizeToXOnly(pubkey);
        } else if (key_str.find("pub") != std::string::npos || key_str[0] == '[') {
            // Extended public key (xpub/tpub) potentially with origin info
            // For these test vectors, we're testing key extraction, not descriptor parsing.
            // We strip the derivation path suffix and extract just the xpub/tpub key.
            std::string xpub_only = key_str;

            // Remove origin prefix if present: [fingerprint/path]
            if (xpub_only[0] == '[') {
                size_t close = xpub_only.find(']');
                if (close != std::string::npos) {
                    xpub_only = xpub_only.substr(close + 1);
                }
            }

            // Remove derivation suffix if present: /<0;1>/* or /0/* etc
            size_t slash = xpub_only.find('/');
            if (slash != std::string::npos) {
                xpub_only = xpub_only.substr(0, slash);
            }

            // Parse the extended public key (uses RegTest chain so tpub prefix works)
            CExtPubKey ext_pubkey = DecodeExtPubKey(xpub_only);
            if (ext_pubkey.pubkey.IsValid()) {
                result = NormalizeToXOnly(ext_pubkey.pubkey);
            } else {
                // Fallback to raw base58 decoding for xpub (mainnet) keys
                std::vector<unsigned char> decoded_data;
                if (!DecodeBase58Check(xpub_only, decoded_data, 78)) {
                    BOOST_FAIL("Failed to decode xpub base58: " + xpub_only);
                }
                BOOST_REQUIRE_EQUAL(decoded_data.size(), 78u);
                CPubKey pubkey;
                pubkey.Set(decoded_data.begin() + 45, decoded_data.end());
                BOOST_REQUIRE_MESSAGE(pubkey.IsValid(), "Invalid pubkey in xpub");
                result = NormalizeToXOnly(pubkey);
            }
        }

        BOOST_CHECK_MESSAGE(result == expected,
            description << ": expected " << expected_hex << " got " << HexStr(result));
    }
}

BOOST_AUTO_TEST_CASE(secret_derivation_test)
{
    // Test secret derivation using BIP test vectors
    UniValue vectors = read_json(json_tests::bip_encrypted_backup_encryption_secret);

    for (size_t i = 0; i < vectors.size(); ++i) {
        const UniValue& vec = vectors[i];
        std::string description = vec["description"].get_str();
        const UniValue& keys_arr = vec["keys"];

        BOOST_TEST_MESSAGE("Testing: " << description);

        // Parse keys
        std::vector<uint256> keys;
        for (size_t j = 0; j < keys_arr.size(); ++j) {
            auto key_bytes = ParseHex(keys_arr[j].get_str());
            BOOST_REQUIRE_EQUAL(key_bytes.size(), 32u);
            uint256 key;
            std::memcpy(key.data(), key_bytes.data(), 32);
            keys.push_back(key);
        }

        // Compute secrets
        std::vector<uint256> sorted_keys = keys;
        std::sort(sorted_keys.begin(), sorted_keys.end());
        // Remove duplicates
        sorted_keys.erase(std::unique(sorted_keys.begin(), sorted_keys.end()), sorted_keys.end());

        uint256 decryption_secret = ComputeDecryptionSecret(sorted_keys);
        BOOST_CHECK(!decryption_secret.IsNull());

        auto individual_secrets = ComputeAllIndividualSecrets(decryption_secret, sorted_keys);
        BOOST_CHECK_EQUAL(individual_secrets.size(), sorted_keys.size());

        // TODO: When BIP test vectors are updated with actual expected values,
        // compare decryption_secret and individual_secrets against them.
        // Currently the BIP has "TBD" placeholders.
        std::string expected_secret = vec["decryption_secret"].get_str();
        if (expected_secret != "TBD") {
            auto expected_bytes = ParseHex(expected_secret);
            BOOST_REQUIRE_EQUAL(expected_bytes.size(), 32u);
            uint256 expected;
            std::memcpy(expected.data(), expected_bytes.data(), 32);
            BOOST_CHECK_MESSAGE(decryption_secret == expected,
                description << ": decryption_secret mismatch");
        }

        // Verify XOR property: for each key, ci XOR si = s
        for (size_t j = 0; j < sorted_keys.size(); ++j) {
            uint256 si = ComputeIndividualSecret(sorted_keys[j]);
            uint256 reconstructed;
            for (size_t k = 0; k < 32; ++k) {
                reconstructed.data()[k] = individual_secrets[j].data()[k] ^ si.data()[k];
            }
            BOOST_CHECK_MESSAGE(reconstructed == decryption_secret,
                description << ": XOR reconstruction failed for key " << j);
        }
    }
}

BOOST_AUTO_TEST_CASE(nums_point_test)
{
    // Verify NUMS point detection
    auto nums_bytes = ParseHex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0");
    uint256 nums_key;
    std::memcpy(nums_key.data(), nums_bytes.data(), 32);

    BOOST_CHECK(IsNUMSPoint(nums_key));

    // Random key should not be NUMS
    uint256 random_key;
    GetStrongRandBytes(random_key);
    BOOST_CHECK(!IsNUMSPoint(random_key));
}

BOOST_AUTO_TEST_CASE(derivation_path_encoding_test)
{
    // Test derivation path encoding using BIP test vectors
    UniValue vectors = read_json(json_tests::bip_encrypted_backup_derivation_path);

    for (size_t i = 0; i < vectors.size(); ++i) {
        const UniValue& vec = vectors[i];
        std::string description = vec["description"].get_str();
        const UniValue& paths_arr = vec["paths"];

        BOOST_TEST_MESSAGE("Testing: " << description);

        // Parse paths
        std::vector<DerivationPath> paths;
        bool parse_failed = false;
        for (size_t j = 0; j < paths_arr.size(); ++j) {
            auto path_result = ParseDerivationPath(paths_arr[j].get_str());
            if (!path_result) {
                parse_failed = true;
                break;
            }
            paths.push_back(*path_result);
        }

        // Check if this test vector should fail
        if (vec["expected"].isNull()) {
            if (!parse_failed) {
                auto encoded_result = EncodeDerivationPaths(paths);
                BOOST_CHECK_MESSAGE(!encoded_result,
                    description << ": expected failure but got success");
            }
            continue;
        }

        BOOST_REQUIRE_MESSAGE(!parse_failed, description << ": unexpected parse failure");
        std::string expected_hex = vec["expected"].get_str();

        // Encode
        auto encoded_result = EncodeDerivationPaths(paths);
        BOOST_REQUIRE_MESSAGE(encoded_result, util::ErrorString(encoded_result).original);

        std::string result_hex = HexStr(*encoded_result);
        BOOST_CHECK_MESSAGE(result_hex == expected_hex,
            description << ": expected " << expected_hex << " got " << result_hex);

        // Test round-trip decode
        auto decoded_result = DecodeDerivationPaths(*encoded_result);
        BOOST_REQUIRE_MESSAGE(decoded_result, util::ErrorString(decoded_result).original);
        BOOST_CHECK_EQUAL(decoded_result->size(), paths.size());
    }
}

BOOST_AUTO_TEST_CASE(individual_secrets_encoding_test)
{
    // Test individual secrets encoding using BIP test vectors
    UniValue vectors = read_json(json_tests::bip_encrypted_backup_individual_secrets);

    for (size_t i = 0; i < vectors.size(); ++i) {
        const UniValue& vec = vectors[i];
        std::string description = vec["description"].get_str();

        BOOST_TEST_MESSAGE("Testing: " << description);

        const UniValue& secrets_arr = vec["secrets"];

        // Parse secrets
        std::vector<uint256> secrets;
        for (size_t j = 0; j < secrets_arr.size(); ++j) {
            auto secret_bytes = ParseHex(secrets_arr[j].get_str());
            if (secret_bytes.size() == 32) {
                uint256 secret;
                std::memcpy(secret.data(), secret_bytes.data(), 32);
                secrets.push_back(secret);
            }
        }

        // Check if this should fail
        if (vec["expected"].isNull()) {
            auto encoded_result = EncodeIndividualSecrets(secrets);
            BOOST_CHECK_MESSAGE(!encoded_result,
                description << ": expected failure but got success");
            continue;
        }

        std::string expected_hex = vec["expected"].get_str();

        // Encode
        auto encoded_result = EncodeIndividualSecrets(secrets);
        BOOST_REQUIRE_MESSAGE(encoded_result, util::ErrorString(encoded_result).original);

        std::string result_hex = HexStr(*encoded_result);
        BOOST_CHECK_MESSAGE(result_hex == expected_hex,
            description << ": expected " << expected_hex << " got " << result_hex);

        // Test round-trip decode
        auto decoded_result = DecodeIndividualSecrets(*encoded_result);
        BOOST_REQUIRE_MESSAGE(decoded_result, util::ErrorString(decoded_result).original);
        BOOST_CHECK_EQUAL(decoded_result->size(), secrets.size());
    }
}

BOOST_AUTO_TEST_CASE(content_type_encoding_test)
{
    // Test content type encoding using BIP test vectors
    UniValue vectors = read_json(json_tests::bip_encrypted_backup_content_type);

    for (size_t i = 0; i < vectors.size(); ++i) {
        const UniValue& vec = vectors[i];
        std::string description = vec["description"].get_str();
        bool valid = vec["valid"].get_bool();
        std::string content_hex = vec["content"].get_str();

        BOOST_TEST_MESSAGE("Testing: " << description);

        auto content_bytes = ParseHex(content_hex);

        // Try to decode
        auto decoded_result = DecodeContent(content_bytes);

        if (!valid) {
            BOOST_CHECK_MESSAGE(!decoded_result,
                description << ": expected decode failure but got success");
        } else {
            BOOST_REQUIRE_MESSAGE(decoded_result,
                description << ": expected decode success but got: " <<
                (decoded_result ? "" : util::ErrorString(decoded_result).original));

            auto [content, bytes_consumed] = *decoded_result;

            // Only test round-trip for known types
            if (content.type == ContentType::BIP_NUMBER ||
                content.type == ContentType::VENDOR_SPECIFIC) {
                auto reencoded = EncodeContent(content);
                BOOST_REQUIRE_MESSAGE(reencoded, util::ErrorString(reencoded).original);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(chacha20poly1305_roundtrip_test)
{
    // Test basic encryption/decryption roundtrip
    std::vector<uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
    uint256 secret;
    GetStrongRandBytes(secret);

    std::array<uint8_t, ENCRYPTED_BACKUP_NONCE_SIZE> nonce;
    GetStrongRandBytes(nonce);

    // Encrypt
    auto ciphertext = EncryptChaCha20Poly1305(plaintext, secret, nonce);
    BOOST_CHECK_EQUAL(ciphertext.size(), plaintext.size() + ENCRYPTED_BACKUP_TAG_SIZE);

    // Decrypt with correct key
    auto decrypted = DecryptChaCha20Poly1305(ciphertext, secret, nonce);
    BOOST_REQUIRE(decrypted.has_value());
    BOOST_CHECK(decrypted.value() == plaintext);

    // Decrypt with wrong key should fail
    uint256 wrong_secret;
    GetStrongRandBytes(wrong_secret);
    auto decrypted_wrong = DecryptChaCha20Poly1305(ciphertext, wrong_secret, nonce);
    BOOST_CHECK(!decrypted_wrong.has_value());
}

BOOST_AUTO_TEST_CASE(full_backup_roundtrip_test)
{
    // Test full backup creation and decryption with a real descriptor
    // Use testnet tpub since we're running on RegTest
    std::string descriptor = "wpkh([d34db33f/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*)";

    // Create backup
    EncryptedBackupContent content;
    content.type = ContentType::BIP_NUMBER;
    content.bip_number = BIP_DESCRIPTORS;

    std::vector<uint8_t> plaintext(descriptor.begin(), descriptor.end());

    auto backup_result = CreateEncryptedBackup(descriptor, plaintext, content, {});
    BOOST_REQUIRE_MESSAGE(backup_result, util::ErrorString(backup_result).original);

    // Encode to binary
    auto encoded = EncodeEncryptedBackup(*backup_result);
    BOOST_CHECK(!encoded.empty());

    // Check magic bytes
    BOOST_CHECK_EQUAL(encoded[0], 'B');
    BOOST_CHECK_EQUAL(encoded[1], 'I');
    BOOST_CHECK_EQUAL(encoded[2], 'P');

    // Decode back
    auto decoded_result = DecodeEncryptedBackup(encoded);
    BOOST_REQUIRE_MESSAGE(decoded_result, util::ErrorString(decoded_result).original);

    // Decrypt using the same descriptor
    auto decrypted = DecryptBackupWithDescriptor(*decoded_result, descriptor);
    BOOST_REQUIRE_MESSAGE(decrypted, util::ErrorString(decrypted).original);

    // Verify plaintext matches
    std::string decrypted_str(decrypted->begin(), decrypted->end());
    BOOST_CHECK_EQUAL(decrypted_str, descriptor);
}

BOOST_AUTO_TEST_CASE(base64_encoding_test)
{
    // Test base64 encoding roundtrip
    // Use testnet tpub since we're running on RegTest
    std::string descriptor = "wpkh([d34db33f/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*)";

    EncryptedBackupContent content;
    content.type = ContentType::BIP_NUMBER;
    content.bip_number = BIP_DESCRIPTORS;

    std::vector<uint8_t> plaintext(descriptor.begin(), descriptor.end());

    auto backup_result = CreateEncryptedBackup(descriptor, plaintext, content, {});
    BOOST_REQUIRE_MESSAGE(backup_result, util::ErrorString(backup_result).original);

    // Encode to base64
    std::string base64_str = EncodeEncryptedBackupBase64(*backup_result);
    BOOST_CHECK(!base64_str.empty());

    // Decode from base64
    auto decoded_result = DecodeEncryptedBackupBase64(base64_str);
    BOOST_REQUIRE_MESSAGE(decoded_result, util::ErrorString(decoded_result).original);

    // Decrypt
    auto decrypted = DecryptBackupWithDescriptor(*decoded_result, descriptor);
    BOOST_REQUIRE_MESSAGE(decrypted, util::ErrorString(decrypted).original);

    std::string decrypted_str(decrypted->begin(), decrypted->end());
    BOOST_CHECK_EQUAL(decrypted_str, descriptor);
}

BOOST_AUTO_TEST_CASE(wrong_key_decryption_test)
{
    // Test that decryption fails with wrong key
    // Use testnet tpub keys since we're running on RegTest
    std::string descriptor1 = "wpkh([11111111/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*)";
    std::string descriptor2 = "wpkh([22222222/84h/1h/0h]tpubDCBEcmVKbfC9KfdydyLbJ2gfNL88grZu1XcWSW9ytTM6fitvaRmVyr8Ddf7SjZ2ZfMx9RicjYAXhuh3fmLiVLPodPEqnQQURUfrBKiiVZc8/0/*)";

    EncryptedBackupContent content;
    content.type = ContentType::BIP_NUMBER;
    content.bip_number = BIP_DESCRIPTORS;

    std::vector<uint8_t> plaintext(descriptor1.begin(), descriptor1.end());

    // Create backup with descriptor1
    auto backup_result = CreateEncryptedBackup(descriptor1, plaintext, content, {});
    BOOST_REQUIRE_MESSAGE(backup_result, util::ErrorString(backup_result).original);

    // Try to decrypt with descriptor2 - should fail
    auto decrypted = DecryptBackupWithDescriptor(*backup_result, descriptor2);
    BOOST_CHECK_MESSAGE(!decrypted, "Decryption should fail with wrong key");
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet

// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/encrypted_backup.h>

#include <crypto/chacha20poly1305.h>
#include <test/data/bip138_keys_types.json.h>
#include <test/data/bip138_encryption_secret.json.h>
#include <test/data/bip138_derivation_path.json.h>
#include <test/data/bip138_individual_secrets.json.h>
#include <test/data/bip138_content_type.json.h>
#include <test/data/bip138_chacha20poly1305_encryption.json.h>

#include <test/util/json.h>
#include <test/util/setup_common.h>
#include <util/bip32.h>
#include <util/strencodings.h>

#include <span.h>
#include <streams.h>

#include <boost/test/unit_test.hpp>
#include <univalue.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <string_view>

namespace wallet {

// Use RegTest chain type so tpub keys (testnet prefixes) can be parsed
struct EncryptedBackupTestingSetup : public BasicTestingSetup {
    EncryptedBackupTestingSetup() : BasicTestingSetup(ChainType::REGTEST) {}
};

BOOST_FIXTURE_TEST_SUITE(encrypted_backup_tests, EncryptedBackupTestingSetup)

static std::optional<XOnlyPubKey> HexPublicKeyToXOnly(std::string_view key_str)
{
    auto key_bytes = TryParseHex<uint8_t>(key_str);
    if (!key_bytes) return std::nullopt;
    if (key_bytes->size() == XOnlyPubKey::size()) {
        return XOnlyPubKey{std::span<const unsigned char>{*key_bytes}};
    }
    CPubKey pubkey{std::span{*key_bytes}};
    if (!pubkey.IsFullyValid() || !pubkey.IsValidNonHybrid()) {
        return std::nullopt;
    }
    return XOnlyPubKey{pubkey};
}

static std::string DescriptorForKeyExpression(const std::string& key_str)
{
    if (key_str.starts_with("tr(")) {
        return key_str;
    }
    if (key_str.size() == 64 && IsHex(key_str)) {
        return "rawtr(" + key_str + ")";
    }
    if (key_str.size() == 130 && key_str.starts_with("04") && IsHex(key_str)) {
        return "pk(" + key_str + ")";
    }
    return "wpkh(" + key_str + ")";
}

static bool ParseNonEmptyHDKeypath(const std::string& path_str, DerivationPath& path)
{
    return ParseHDKeypath(path_str, path) && !path.empty();
}

static AEADChaCha20Poly1305::Nonce96 ReadAEADNonce(std::span<const uint8_t, ENCRYPTED_BACKUP_NONCE_SIZE> nonce)
{
    AEADChaCha20Poly1305::Nonce96 nonce96;
    SpanReader{std::span{nonce}} >> nonce96.first >> nonce96.second;
    return nonce96;
}

BOOST_AUTO_TEST_CASE(key_normalization_test)
{
    // Test BIP key extraction using BIP test vectors
    UniValue vectors = read_json(json_tests::bip138_keys_types);

    for (size_t i = 0; i < vectors.size(); ++i) {
        const UniValue& vec = vectors[i];
        std::string description = vec["description"].get_str();
        std::string key_str = vec["key"].get_str();

        BOOST_TEST_MESSAGE("Testing: " << description);

        auto keys_result = ExtractKeysFromDescriptor(DescriptorForKeyExpression(key_str));

        if (vec["expected"].isNull()) {
            BOOST_CHECK_MESSAGE(!keys_result, description << ": expected key extraction failure");
            continue;
        }

        BOOST_REQUIRE_MESSAGE(keys_result, util::ErrorString(keys_result).original);

        const UniValue& expected = vec["expected"];
        std::vector<XOnlyPubKey> expected_keys;
        const size_t expected_size{expected.isArray() ? expected.size() : 1};
        expected_keys.reserve(expected_size);
        for (size_t j = 0; j < expected_size; ++j) {
            const std::string expected_hex{expected.isArray() ? expected[j].get_str() : expected.get_str()};
            auto expected_bytes = ParseHex(expected_hex);
            BOOST_REQUIRE_EQUAL(expected_bytes.size(), 32u);
            expected_keys.emplace_back(std::span<const unsigned char>{expected_bytes});
        }

        BOOST_REQUIRE_EQUAL(keys_result->size(), expected_keys.size());
        BOOST_CHECK_MESSAGE(*keys_result == expected_keys,
            description << ": expected keys did not match");
    }
}

BOOST_AUTO_TEST_CASE(secret_derivation_test)
{
    // Test secret derivation using BIP test vectors
    UniValue vectors = read_json(json_tests::bip138_encryption_secret);

    for (const UniValue& vec : vectors.getValues()) {
        std::string description = vec["description"].get_str();
        const UniValue& keys_arr = vec["keys"];

        BOOST_TEST_MESSAGE("Testing: " << description);

        std::vector<XOnlyPubKey> keys;
        for (const UniValue& key_val : keys_arr.getValues()) {
            auto key = HexPublicKeyToXOnly(key_val.get_str());
            BOOST_REQUIRE_MESSAGE(key, description << ": invalid public key");
            keys.push_back(*key);
        }

        std::vector<XOnlyPubKey> sorted_keys = keys;
        std::sort(sorted_keys.begin(), sorted_keys.end());
        sorted_keys.erase(std::unique(sorted_keys.begin(), sorted_keys.end()), sorted_keys.end());

        uint256 decryption_secret = ComputeDecryptionSecret(sorted_keys);
        std::string expected_secret = vec["decryption_secret"].get_str();
        auto expected_secret_bytes = ParseHex(expected_secret);
        BOOST_REQUIRE_EQUAL(expected_secret_bytes.size(), uint256::size());
        uint256 expected_decryption_secret{std::span<const unsigned char>{expected_secret_bytes}};
        BOOST_CHECK_MESSAGE(decryption_secret == expected_decryption_secret,
            description << ": decryption_secret mismatch");

        auto individual_secrets = ComputeAllIndividualSecrets(decryption_secret, sorted_keys);
        BOOST_CHECK_EQUAL(individual_secrets.size(), sorted_keys.size());

        const UniValue& expected_individual_secrets = vec["individual_secrets"];
        BOOST_REQUIRE_EQUAL(expected_individual_secrets.size(), individual_secrets.size());
        for (size_t j = 0; j < expected_individual_secrets.size(); ++j) {
            auto expected_bytes = ParseHex(expected_individual_secrets[j].get_str());
            BOOST_REQUIRE_EQUAL(expected_bytes.size(), uint256::size());
            uint256 expected{std::span<const unsigned char>{expected_bytes}};
            BOOST_CHECK_MESSAGE(individual_secrets[j] == expected,
                description << ": individual_secret mismatch for key " << j);
        }

        // Verify XOR property: for each key, ci XOR si = s
        for (size_t j = 0; j < sorted_keys.size(); ++j) {
            uint256 si = ComputeIndividualSecret(sorted_keys[j]);
            uint256 reconstructed;
            std::transform(individual_secrets[j].begin(), individual_secrets[j].end(), si.begin(), reconstructed.begin(),
                           [](uint8_t a, uint8_t b) { return a ^ b; });
            BOOST_CHECK_MESSAGE(reconstructed == decryption_secret,
                description << ": XOR reconstruction failed for key " << j);
        }
    }
}

BOOST_AUTO_TEST_CASE(derivation_path_encoding_test)
{
    // Test derivation path encoding using BIP test vectors
    UniValue vectors = read_json(json_tests::bip138_derivation_path);

    for (size_t i = 0; i < vectors.size(); ++i) {
        const UniValue& vec = vectors[i];
        std::string description = vec["description"].get_str();
        const UniValue& paths_arr = vec["paths"];

        BOOST_TEST_MESSAGE("Testing: " << description);

        // Parse paths
        std::vector<DerivationPath> paths;
        bool parse_failed = false;
        for (size_t j = 0; j < paths_arr.size(); ++j) {
            DerivationPath path;
            if (!ParseNonEmptyHDKeypath(paths_arr[j].get_str(), path)) {
                parse_failed = true;
                break;
            }
            paths.push_back(path);
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
    UniValue vectors = read_json(json_tests::bip138_individual_secrets);

    for (size_t i = 0; i < vectors.size(); ++i) {
        const UniValue& vec = vectors[i];
        std::string description = vec["description"].get_str();

        BOOST_TEST_MESSAGE("Testing: " << description);

        const UniValue& secrets_arr = vec["secrets"];

        std::vector<uint256> secrets;
        bool parse_failed = false;
        for (size_t j = 0; j < secrets_arr.size(); ++j) {
            auto secret_bytes = ParseHex(secrets_arr[j].get_str());
            if (secret_bytes.size() != 32) {
                parse_failed = true;
                break;
            }
            uint256 secret;
            std::memcpy(secret.data(), secret_bytes.data(), 32);
            secrets.push_back(secret);
        }

        // Check if this should fail
        if (vec["expected"].isNull()) {
            if (parse_failed) continue;
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
    UniValue vectors = read_json(json_tests::bip138_content_type);

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

            BOOST_CHECK_EQUAL(bytes_consumed, content_bytes.size());
            BOOST_REQUIRE_MESSAGE(content.has_value(), description << ": expected decoded content");

            if (content->type == ContentType::BIP_NUMBER) {
                BOOST_CHECK_EQUAL(static_cast<int>(content->bip_number), (content_bytes[1] << 8) | content_bytes[2]);
            } else if (content->type == ContentType::VENDOR_SPECIFIC) {
                BOOST_CHECK_EQUAL(HexStr(content->payload), content_hex.substr(4));
            }

            auto reencoded = EncodeContent(*content);
            BOOST_REQUIRE_MESSAGE(reencoded, util::ErrorString(reencoded).original);
            BOOST_CHECK_EQUAL(HexStr(*reencoded), content_hex);
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

    AEADChaCha20Poly1305 aead{MakeByteSpan(secret)};
    std::vector<uint8_t> ciphertext(plaintext.size() + AEADChaCha20Poly1305::EXPANSION);
    aead.Encrypt(MakeByteSpan(plaintext), {}, ReadAEADNonce(nonce), MakeWritableByteSpan(ciphertext));
    BOOST_CHECK_EQUAL(ciphertext.size(), plaintext.size() + ENCRYPTED_BACKUP_TAG_SIZE);

    std::vector<uint8_t> decrypted(plaintext.size());
    BOOST_CHECK(aead.Decrypt(MakeByteSpan(ciphertext), {}, ReadAEADNonce(nonce), MakeWritableByteSpan(decrypted)));
    BOOST_CHECK(decrypted == plaintext);

    uint256 wrong_secret;
    GetStrongRandBytes(wrong_secret);
    AEADChaCha20Poly1305 wrong_aead{MakeByteSpan(wrong_secret)};
    BOOST_CHECK(!wrong_aead.Decrypt(MakeByteSpan(ciphertext), {}, ReadAEADNonce(nonce), MakeWritableByteSpan(decrypted)));
}

BOOST_AUTO_TEST_CASE(chacha20poly1305_vector_test)
{
    UniValue vectors = read_json(json_tests::bip138_chacha20poly1305_encryption);

    for (size_t i = 0; i < vectors.size(); ++i) {
        const UniValue& vec = vectors[i];
        std::string description = vec["description"].get_str();

        BOOST_TEST_MESSAGE("Testing: " << description);

        auto nonce_bytes = ParseHex(vec["nonce"].get_str());
        BOOST_REQUIRE_EQUAL(nonce_bytes.size(), ENCRYPTED_BACKUP_NONCE_SIZE);
        std::array<uint8_t, ENCRYPTED_BACKUP_NONCE_SIZE> nonce;
        std::memcpy(nonce.data(), nonce_bytes.data(), nonce.size());

        auto secret_bytes = ParseHex(vec["secret"].get_str());
        BOOST_REQUIRE_EQUAL(secret_bytes.size(), 32u);
        uint256 secret;
        std::memcpy(secret.data(), secret_bytes.data(), 32);

        if (vec["ciphertext"].isNull()) {
            BOOST_CHECK_MESSAGE(vec["plaintext"].get_str().empty() ||
                    std::all_of(nonce.begin(), nonce.end(), [](uint8_t byte) { return byte == 0; }),
                description << ": expected invalid input");
            continue;
        }

        auto plaintext = ParseHex(vec["plaintext"].get_str());
        BOOST_REQUIRE(!plaintext.empty());
        BOOST_REQUIRE(!std::all_of(nonce.begin(), nonce.end(), [](uint8_t byte) { return byte == 0; }));

        AEADChaCha20Poly1305 aead{MakeByteSpan(secret)};
        std::vector<uint8_t> ciphertext(plaintext.size() + AEADChaCha20Poly1305::EXPANSION);
        aead.Encrypt(MakeByteSpan(plaintext), {}, ReadAEADNonce(nonce), MakeWritableByteSpan(ciphertext));
        BOOST_CHECK_EQUAL(HexStr(ciphertext), vec["ciphertext"].get_str());

        std::vector<uint8_t> decrypted(plaintext.size());
        BOOST_CHECK(aead.Decrypt(MakeByteSpan(ciphertext), {}, ReadAEADNonce(nonce), MakeWritableByteSpan(decrypted)));
        BOOST_CHECK(decrypted == plaintext);
    }
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet

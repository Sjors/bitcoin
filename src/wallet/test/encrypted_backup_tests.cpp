// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/encrypted_backup.h>

#include <crypto/chacha20poly1305.h>
#include <interfaces/wallet.h>
#include <test/data/bip138_recipient_keys.json.h>
#include <test/data/bip138_encryption_secret.json.h>
#include <test/data/bip138_derivation_path.json.h>
#include <test/data/bip138_individual_secrets.json.h>
#include <test/data/bip138_content_type.json.h>
#include <test/data/bip138_payload.json.h>
#include <test/data/bip138_chacha20poly1305_encryption.json.h>
#include <test/data/bip138_encrypted_backup.json.h>
#include <test/data/bip138_bip380_descriptor_backup.json.h>
#include <test/data/bip138_bip380_descriptor_backup.txt.h>

#include <test/util/json.h>
#include <test/util/setup_common.h>
#include <util/bip32.h>
#include <util/strencodings.h>
#include <wallet/context.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <span.h>
#include <streams.h>

#include <boost/test/unit_test.hpp>
#include <univalue.h>

#include <algorithm>
#include <cstddef>
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
    const UniValue vectors{read_json(json_tests::bip138_recipient_keys)};
    // The first nine entries preserve the original BIP key-expression vectors.
    BOOST_REQUIRE(vectors.size() >= 9);
    for (size_t i{0}; i < 9; ++i) {
        const auto& vec{vectors[i]};
        BOOST_TEST_CONTEXT(vec["description"].get_str()) {
            BOOST_REQUIRE_EQUAL(vec["descriptors"].size(), 1);
            const auto keys{ExtractKeysFromDescriptor(vec["descriptors"][0].get_str())};
            if (vec["expected_keys"].isNull()) {
                BOOST_CHECK(!keys);
                continue;
            }
            BOOST_REQUIRE_MESSAGE(keys, util::ErrorString(keys).original);
            std::vector<XOnlyPubKey> expected_keys;
            for (const auto& expected : vec["expected_keys"].getValues()) {
                const auto bytes{ParseHex(expected.get_str())};
                BOOST_REQUIRE_EQUAL(bytes.size(), XOnlyPubKey::size());
                expected_keys.emplace_back(std::span<const unsigned char>{bytes});
            }
            BOOST_CHECK(*keys == expected_keys);
        }
    }
}

BOOST_AUTO_TEST_CASE(recipient_vectors_test)
{
    // BIP138 recipient selection vectors.
    const UniValue vectors{read_json(json_tests::bip138_recipient_keys)};
    for (const auto& vec : vectors.getValues()) {
        const std::string description{vec["description"].get_str()};
        BOOST_TEST_CONTEXT(description) {
            std::vector<std::string> descriptors;
            UniValue sets{UniValue::VARR};
            for (const auto& descriptor : vec["descriptors"].getValues()) {
                descriptors.push_back(descriptor.get_str());
                UniValue set{UniValue::VOBJ};
                set.pushKV("descriptor", descriptor.get_str());
                sets.push_back(std::move(set));
            }
            std::vector<XOnlyPubKey> expected_keys;
            if (!vec["expected_keys"].isNull()) {
                for (const auto& expected : vec["expected_keys"].getValues()) {
                    BOOST_REQUIRE_EQUAL(expected.get_str().size(), 64);
                    const auto key{HexPublicKeyToXOnly(expected.get_str())};
                    BOOST_REQUIRE(key);
                    expected_keys.push_back(*key);
                }
            }
            UniValue document{UniValue::VOBJ};
            document.pushKV("version", 1);
            document.pushKV("descriptor_sets", std::move(sets));
            const std::string plaintext{document.write()};
            const EncryptedBackupContentType content{.type = DataType::BIP_NUMBER, .bip_number = BIP_DESCRIPTORS, .payload = {}};
            const auto backup{CreateEncryptedBackup(descriptors, {UCharCast(plaintext.data()), plaintext.size()}, content, {}, /*decoys=*/false)};

            // Core refuses excluded expressions instead of warning and keeping
            // the remaining eligible recipients. The exposed MuSig participant
            // vector therefore fails here despite a nonempty recipient set.
            if (expected_keys.empty() || description == "MuSig participant exposed in a script leaf") {
                BOOST_REQUIRE(!backup);
                continue;
            }
            BOOST_REQUIRE_MESSAGE(backup, util::ErrorString(backup).original);
            for (const auto& key : expected_keys) {
                const auto decrypted{DecryptBackupWithKey(*backup, key)};
                BOOST_REQUIRE(decrypted);
                BOOST_CHECK_EQUAL(std::string(decrypted->begin(), decrypted->end()), plaintext);
            }
            // Exact secret comparison checks normalization and deduplication,
            // including roots shared between receive and change descriptors.
            const auto secret{ComputeDecryptionSecret(expected_keys)};
            const auto expected_secrets{ComputeAllIndividualSecrets(secret, expected_keys)};
            BOOST_CHECK(backup->individual_secrets == expected_secrets);
        }
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

        // Test round-trip decode (decoded paths are already sorted and
        // deduplicated, so re-encoding must reproduce the expected bytes)
        auto decoded_result = DecodeDerivationPaths(*encoded_result);
        BOOST_REQUIRE_MESSAGE(decoded_result, util::ErrorString(decoded_result).original);
        auto reencoded_result = EncodeDerivationPaths(*decoded_result);
        BOOST_REQUIRE_MESSAGE(reencoded_result, util::ErrorString(reencoded_result).original);
        BOOST_CHECK_EQUAL(HexStr(*reencoded_result), expected_hex);
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

        // Test round-trip decode (decoded secrets are already sorted and
        // deduplicated, so re-encoding must reproduce the expected bytes)
        auto decoded_result = DecodeIndividualSecrets(*encoded_result);
        BOOST_REQUIRE_MESSAGE(decoded_result, util::ErrorString(decoded_result).original);
        auto reencoded_result = EncodeIndividualSecrets(*decoded_result);
        BOOST_REQUIRE_MESSAGE(reencoded_result, util::ErrorString(reencoded_result).original);
        BOOST_CHECK_EQUAL(HexStr(*reencoded_result), expected_hex);
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
        auto decoded_result = DecodeContentType(content_bytes);

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

            if (content->type == DataType::BIP_NUMBER) {
                BOOST_CHECK_EQUAL(static_cast<int>(content->bip_number), (content_bytes[1] << 8) | content_bytes[2]);
            } else if (content->type == DataType::VENDOR_SPECIFIC) {
                BOOST_CHECK_EQUAL(HexStr(content->payload), content_hex.substr(4));
            }

            auto reencoded = EncodeContentType(*content);
            BOOST_REQUIRE_MESSAGE(reencoded, util::ErrorString(reencoded).original);
            BOOST_CHECK_EQUAL(HexStr(*reencoded), content_hex);
        }
    }
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

        // BIP138 restrictions are exercised in chacha20poly1305_invalid_backup_vectors_test.
        // The cipher itself accepts empty plaintext and an all-zero nonce.
        if (vec["ciphertext"].isNull()) continue;

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

BOOST_AUTO_TEST_CASE(chacha20poly1305_invalid_backup_vectors_test)
{
    const UniValue vectors{read_json(json_tests::bip138_chacha20poly1305_encryption)};
    const XOnlyPubKey key{ParseHex("8b42cd4776376c82791b494155151f56c2d7b471e0c7a526a7ce60dd872e3867")};
    for (const auto& vec : vectors.getValues()) {
        if (!vec["ciphertext"].isNull()) continue;
        BOOST_TEST_CONTEXT(vec["description"].get_str()) {
            const auto plaintext{ParseHex(vec["plaintext"].get_str())};
            const auto secret_bytes{ParseHex(vec["secret"].get_str())};
            BOOST_REQUIRE_EQUAL(secret_bytes.size(), uint256::size());
            const uint256 secret{std::span<const unsigned char>{secret_bytes}};
            const auto nonce{ParseHex(vec["nonce"].get_str())};
            EncryptedBackup backup{};
            BOOST_REQUIRE_EQUAL(nonce.size(), backup.nonce.size());
            std::copy(nonce.begin(), nonce.end(), backup.nonce.begin());
            backup.individual_secrets = ComputeAllIndividualSecrets(secret, {key});
            backup.ciphertext.resize(plaintext.size() + AEADChaCha20Poly1305::EXPANSION);
            AEADChaCha20Poly1305 aead{MakeByteSpan(secret)};
            aead.Encrypt(MakeByteSpan(plaintext), {}, ReadAEADNonce(backup.nonce), MakeWritableByteSpan(backup.ciphertext));

            const auto decoded{DecodeEncryptedBackup(EncodeEncryptedBackup(backup))};
            if (std::all_of(nonce.begin(), nonce.end(), [](uint8_t byte) { return byte == 0; })) {
                BOOST_REQUIRE(!decoded);
                BOOST_CHECK_EQUAL(util::ErrorString(decoded).original, "Invalid all-zero nonce");
            } else {
                BOOST_REQUIRE(plaintext.empty());
                BOOST_REQUIRE_MESSAGE(decoded, util::ErrorString(decoded).original);
                // Authentication succeeds, but BIP138 rejects the empty payload.
                std::vector<uint8_t> decrypted(plaintext.size());
                BOOST_REQUIRE(aead.Decrypt(MakeByteSpan(decoded->ciphertext), {}, ReadAEADNonce(decoded->nonce), MakeWritableByteSpan(decrypted)));
                BOOST_CHECK(!DecryptBackupContentsWithKey(*decoded, key));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(full_backup_vector_test)
{
    UniValue vectors = read_json(json_tests::bip138_encrypted_backup);

    for (size_t i = 0; i < vectors.size(); ++i) {
        const UniValue& vec = vectors[i];
        std::string description = vec["description"].get_str();

        BOOST_TEST_MESSAGE("Testing: " << description);

        // Vectors marked invalid carry a crafted encoding that decoders MUST
        // reject; only check that decoding fails (an encoder would never emit
        // such a backup, so re-encoding it is not meaningful).
        if (vec.exists("valid") && !vec["valid"].get_bool()) {
            auto rejected = DecodeEncryptedBackup(ParseHex(vec["expected"].get_str()));
            BOOST_CHECK_MESSAGE(!rejected, description << ": invalid backup must be rejected on decode");
            continue;
        }

        std::vector<XOnlyPubKey> keys;
        const UniValue& keys_arr = vec["keys"];
        for (size_t j = 0; j < keys_arr.size(); ++j) {
            auto key = HexPublicKeyToXOnly(keys_arr[j].get_str());
            BOOST_REQUIRE_MESSAGE(key, description << ": invalid public key");
            keys.push_back(*key);
        }
        std::sort(keys.begin(), keys.end());
        keys.erase(std::unique(keys.begin(), keys.end()), keys.end());

        uint256 decryption_secret = ComputeDecryptionSecret(keys);
        auto individual_secrets = ComputeAllIndividualSecrets(decryption_secret, keys);

        // Decoy secrets pad the count to a bucket boundary; the encoder sorts
        // them in with the real ones.
        if (vec.exists("decoy_individual_secrets")) {
            for (const UniValue& decoy : vec["decoy_individual_secrets"].getValues()) {
                auto decoy_bytes = ParseHex(decoy.get_str());
                BOOST_REQUIRE_EQUAL(decoy_bytes.size(), uint256::size());
                uint256 decoy_secret;
                std::memcpy(decoy_secret.data(), decoy_bytes.data(), decoy_bytes.size());
                individual_secrets.push_back(decoy_secret);
            }
        }

        std::vector<DerivationPath> derivation_paths;
        const UniValue& paths_arr = vec["derivation_paths"];
        for (size_t j = 0; j < paths_arr.size(); ++j) {
            DerivationPath path;
            BOOST_REQUIRE(ParseNonEmptyHDKeypath(paths_arr[j].get_str(), path));
            derivation_paths.push_back(path);
        }
        // Encoders omit common derivation paths, since recovery implementations
        // try them automatically.
        std::erase_if(derivation_paths, IsCommonDerivationPath);

        auto content = ParseHex(vec["content"].get_str());
        std::string plaintext_str = vec["plaintext"].get_str();
        std::vector<uint8_t> payload{content.begin(), content.end()};
        DataStream plaintext_size;
        WriteCompactSize(plaintext_size, plaintext_str.size());
        payload.insert(payload.end(), UCharCast(plaintext_size.data()), UCharCast(plaintext_size.data()) + plaintext_size.size());
        payload.insert(payload.end(), plaintext_str.begin(), plaintext_str.end());

        // Additional CONTENT/LENGTH/PLAINTEXT items packed into the same payload.
        std::vector<std::string> all_plaintexts{plaintext_str};
        if (vec.exists("extra")) {
            for (const UniValue& item : vec["extra"].getValues()) {
                auto extra_content = ParseHex(item["content"].get_str());
                std::string extra_plaintext = item["plaintext"].get_str();
                payload.insert(payload.end(), extra_content.begin(), extra_content.end());
                DataStream extra_size;
                WriteCompactSize(extra_size, extra_plaintext.size());
                payload.insert(payload.end(), UCharCast(extra_size.data()), UCharCast(extra_size.data()) + extra_size.size());
                payload.insert(payload.end(), extra_plaintext.begin(), extra_plaintext.end());
                all_plaintexts.push_back(std::move(extra_plaintext));
            }
        }

        auto nonce_bytes = ParseHex(vec["nonce"].get_str());
        BOOST_REQUIRE_EQUAL(nonce_bytes.size(), ENCRYPTED_BACKUP_NONCE_SIZE);
        std::array<uint8_t, ENCRYPTED_BACKUP_NONCE_SIZE> nonce;
        std::memcpy(nonce.data(), nonce_bytes.data(), nonce.size());

        AEADChaCha20Poly1305 aead{MakeByteSpan(decryption_secret)};
        std::vector<uint8_t> ciphertext(payload.size() + AEADChaCha20Poly1305::EXPANSION);
        aead.Encrypt(MakeByteSpan(payload), {}, ReadAEADNonce(nonce), MakeWritableByteSpan(ciphertext));

        EncryptedBackup backup;
        backup.version = vec["version"].getInt<int>();
        backup.derivation_paths = std::move(derivation_paths);
        backup.individual_secrets = std::move(individual_secrets);
        backup.encryption = static_cast<EncryptionAlgorithm>(vec["encryption"].getInt<int>());
        backup.nonce = nonce;
        backup.ciphertext = std::move(ciphertext);

        const auto encoded = EncodeEncryptedBackup(backup);
        BOOST_CHECK_EQUAL(HexStr(encoded), vec["expected"].get_str());
        BOOST_CHECK_EQUAL(EncodeBase64(encoded), vec["expected_base64"].get_str());

        auto decoded = DecodeEncryptedBackup(ParseHex(vec["expected"].get_str()));
        BOOST_REQUIRE_MESSAGE(decoded, util::ErrorString(decoded).original);
        BOOST_CHECK_EQUAL(HexStr(EncodeEncryptedBackup(*decoded)), vec["expected"].get_str());

        auto decrypted = DecryptBackupWithKey(*decoded, keys.front());
        BOOST_REQUIRE(decrypted.has_value());
        BOOST_CHECK(std::vector<uint8_t>(plaintext_str.begin(), plaintext_str.end()) == *decrypted);

        auto all_decrypted = DecryptBackupContentsWithKey(*decoded, keys.front());
        BOOST_REQUIRE(all_decrypted.has_value());
        BOOST_REQUIRE_EQUAL(all_decrypted->size(), all_plaintexts.size());
        for (size_t j = 0; j < all_plaintexts.size(); ++j) {
            BOOST_CHECK(std::vector<uint8_t>(all_plaintexts[j].begin(), all_plaintexts[j].end()) == all_decrypted->at(j));
        }

        if (vec.exists("trailing")) {
            auto with_trailing = ParseHex(vec["expected"].get_str());
            auto trailing = ParseHex(vec["trailing"].get_str());
            with_trailing.insert(with_trailing.end(), trailing.begin(), trailing.end());
            auto decoded_with_trailing = DecodeEncryptedBackup(with_trailing);
            BOOST_REQUIRE_MESSAGE(decoded_with_trailing, util::ErrorString(decoded_with_trailing).original);
            BOOST_CHECK_EQUAL(HexStr(EncodeEncryptedBackup(*decoded_with_trailing)), vec["expected"].get_str());
        }
    }
}

BOOST_AUTO_TEST_CASE(content_items_padding_roundtrip_test)
{
    // A payload with multiple content items followed by zero padding: the 0x00
    // byte after the last item marks the start of padding, so decryption returns
    // exactly the two items and ignores the trailing zeros.
    const std::string receive_descriptor_1{"wpkh([d34db33f/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*)"};
    const std::string change_descriptor_1{"wpkh([d34db33f/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/1/*)"};

    const EncryptedBackupContentType content{
        .type = DataType::BIP_NUMBER,
        .bip_number = BIP_DESCRIPTORS,
        .payload = {},
    };

    std::vector<uint8_t> payload;
    auto append_plaintext_item = [&](std::string_view plaintext) {
        auto encoded_content{EncodeContentType(content)};
        BOOST_REQUIRE_MESSAGE(encoded_content, util::ErrorString(encoded_content).original);
        payload.insert(payload.end(), encoded_content->begin(), encoded_content->end());

        DataStream plaintext_size;
        WriteCompactSize(plaintext_size, plaintext.size());
        payload.insert(payload.end(), UCharCast(plaintext_size.data()), UCharCast(plaintext_size.data()) + plaintext_size.size());
        payload.insert(payload.end(), plaintext.begin(), plaintext.end());
    };
    append_plaintext_item(receive_descriptor_1);
    append_plaintext_item(change_descriptor_1);
    payload.resize(payload.size() + 32, 0);

    auto backup_result = CreateEncryptedBackup(receive_descriptor_1, {UCharCast(receive_descriptor_1.data()), receive_descriptor_1.size()}, content, {});
    BOOST_REQUIRE_MESSAGE(backup_result, util::ErrorString(backup_result).original);

    auto keys_result = ExtractKeysFromDescriptor(receive_descriptor_1);
    BOOST_REQUIRE_MESSAGE(keys_result, util::ErrorString(keys_result).original);
    uint256 decryption_secret = ComputeDecryptionSecret(*keys_result);

    AEADChaCha20Poly1305 aead{MakeByteSpan(decryption_secret)};
    backup_result->ciphertext.resize(payload.size() + AEADChaCha20Poly1305::EXPANSION);
    aead.Encrypt(MakeByteSpan(payload), {}, ReadAEADNonce(backup_result->nonce), MakeWritableByteSpan(backup_result->ciphertext));

    auto decoded_result = DecodeEncryptedBackup(EncodeEncryptedBackup(*backup_result));
    BOOST_REQUIRE_MESSAGE(decoded_result, util::ErrorString(decoded_result).original);

    auto plaintext_items = DecryptBackupContentsWithKey(*decoded_result, keys_result->front());
    BOOST_REQUIRE(plaintext_items.has_value());
    BOOST_REQUIRE_EQUAL(plaintext_items->size(), 2);
    BOOST_CHECK_EQUAL(std::string(plaintext_items->at(0).begin(), plaintext_items->at(0).end()), receive_descriptor_1);
    BOOST_CHECK_EQUAL(std::string(plaintext_items->at(1).begin(), plaintext_items->at(1).end()), change_descriptor_1);

    auto decrypted = DecryptBackupWithDescriptor(*decoded_result, receive_descriptor_1);
    BOOST_REQUIRE_MESSAGE(decrypted, util::ErrorString(decrypted).original);

    // Every plaintext item is recovered, one per line
    const std::string decrypted_str{decrypted->begin(), decrypted->end()};
    BOOST_CHECK_EQUAL(decrypted_str, receive_descriptor_1 + "\n" + change_descriptor_1);
}

BOOST_AUTO_TEST_CASE(payload_vectors_test)
{
    // BIP138 payload encoding vectors.
    const UniValue vectors{read_json(json_tests::bip138_payload)};
    const XOnlyPubKey key{ParseHex("8b42cd4776376c82791b494155151f56c2d7b471e0c7a526a7ce60dd872e3867")};
    const std::vector<XOnlyPubKey> keys{key};
    const auto secret{ComputeDecryptionSecret(keys)};
    for (const auto& vec : vectors.getValues()) {
        BOOST_TEST_CONTEXT(vec["description"].get_str()) {
            // Authenticate the exact vector plaintext so failures exercise
            // content framing rather than the encryption layer.
            const auto payload{ParseHex(vec["payload"].get_str())};
            EncryptedBackup backup{};
            backup.individual_secrets = ComputeAllIndividualSecrets(secret, keys);
            backup.nonce[0] = 1;
            backup.ciphertext.resize(payload.size() + AEADChaCha20Poly1305::EXPANSION);
            AEADChaCha20Poly1305 aead{MakeByteSpan(secret)};
            aead.Encrypt(MakeByteSpan(payload), {}, ReadAEADNonce(backup.nonce), MakeWritableByteSpan(backup.ciphertext));

            const auto contents{DecryptBackupContentsWithKey(backup, key)};
            BOOST_REQUIRE_EQUAL(contents.has_value(), vec["valid"].get_bool());
            if (!contents) continue;
            const auto& expected{vec["items"].getValues()};
            BOOST_REQUIRE_EQUAL(contents->size(), expected.size());
            for (size_t i{0}; i < expected.size(); ++i) {
                BOOST_CHECK_EQUAL(expected[i]["type"].getInt<int>(), static_cast<int>(DataType::STRING));
                BOOST_CHECK_EQUAL(HexStr(contents->at(i)), expected[i]["content"].get_str());
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(full_backup_roundtrip_test)
{
    const std::string descriptor{"wpkh([d34db33f/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*)"};
    const EncryptedBackupContentType content{.type = DataType::BIP_NUMBER, .bip_number = BIP_DESCRIPTORS, .payload = {}};
    const std::vector<uint8_t> plaintext(descriptor.begin(), descriptor.end());
    const auto backup{CreateEncryptedBackup(descriptor, plaintext, content, {})};
    BOOST_REQUIRE_MESSAGE(backup, util::ErrorString(backup).original);

    // Exercise both backup serialization wrappers with the same generated backup.
    for (const bool base64 : {false, true}) {
        BOOST_TEST_CONTEXT("encoding: " << (base64 ? "Base64" : "binary")) {
            const auto decoded{base64 ? DecodeEncryptedBackupBase64(EncodeEncryptedBackupBase64(*backup))
                                      : DecodeEncryptedBackup(EncodeEncryptedBackup(*backup))};
            BOOST_REQUIRE_MESSAGE(decoded, util::ErrorString(decoded).original);
            const auto decrypted{DecryptBackupWithDescriptor(*decoded, descriptor)};
            BOOST_REQUIRE_MESSAGE(decrypted, util::ErrorString(decrypted).original);
            BOOST_CHECK(*decrypted == plaintext);
        }
    }
}

BOOST_AUTO_TEST_CASE(interface_create_encrypted_descriptor_backup_test)
{
    WalletContext context;
    CWallet wallet(/*chain=*/nullptr, "", CreateMockableWalletDatabase());
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet.SetupDescriptorScriptPubKeyMans();
    }

    std::shared_ptr<CWallet> wallet_ptr{&wallet, [](CWallet*) {}};
    auto wallet_interface{interfaces::MakeWallet(context, wallet_ptr)};
    auto backup{wallet_interface->createEncryptedDescriptorBackup(std::nullopt, /*compact=*/false)};
    BOOST_REQUIRE_MESSAGE(backup, util::ErrorString(backup).original);

    auto metadata{CWallet::GetEncryptedBackupMetadata(*backup)};
    BOOST_REQUIRE_MESSAGE(metadata, util::ErrorString(metadata).original);
    BOOST_CHECK_EQUAL(static_cast<int>(metadata->version), static_cast<int>(ENCRYPTED_BACKUP_VERSION));
    // Account recipients are padded to the smallest decoy bucket.
    BOOST_CHECK_EQUAL(metadata->individual_secret_count, 5);
    BOOST_CHECK_EQUAL(metadata->encryption, "ChaCha20-Poly1305");
    BOOST_CHECK(metadata->derivation_paths.empty());

    auto wallet_backup{interfaces::MakeWalletBackup()};
    auto interface_metadata{wallet_backup->getEncryptedDescriptorBackupMetadata(*backup)};
    BOOST_REQUIRE_MESSAGE(interface_metadata, util::ErrorString(interface_metadata).original);
    BOOST_CHECK_EQUAL(interface_metadata->version, static_cast<int>(ENCRYPTED_BACKUP_VERSION));
    BOOST_CHECK_EQUAL(interface_metadata->individual_secret_count, 5);
    BOOST_CHECK_EQUAL(interface_metadata->encryption, "ChaCha20-Poly1305");
    BOOST_CHECK(interface_metadata->derivation_paths.empty());

    // A compact backup holds a single bare descriptor, so it refuses a
    // wallet with more than one descriptor set
    auto compact_refused{wallet_interface->createEncryptedDescriptorBackup(std::nullopt, /*compact=*/true)};
    BOOST_REQUIRE(!compact_refused);
    BOOST_CHECK_MESSAGE(util::ErrorString(compact_refused).original.find("single descriptor set") != std::string::npos,
                        util::ErrorString(compact_refused).original);

    // A wallet with one descriptor set produces a compact backup: the bare
    // multipath descriptor as plaintext
    const std::string multipath_descriptor{
        "wsh(or_d(pk([9d69155f/48h/1h/0h/2h]tpubDDxT9mkZzWwkKwpGT5fY6iiM9muYTPkTx6Eig8dpHR7TChuGGCWYAHVmpW1ciido5RiFWwjzYsF1GZHkEHg2nrYp3zNtx3QQRkznyLhQ77x/<0;1>/*),"
        "and_v(v:pkh([9d69155f/48h/1h/0h/2h]tpubDDxT9mkZzWwkKwpGT5fY6iiM9muYTPkTx6Eig8dpHR7TChuGGCWYAHVmpW1ciido5RiFWwjzYsF1GZHkEHg2nrYp3zNtx3QQRkznyLhQ77x/<2;3>/*),older(52596))))"};
    CWallet compact_wallet(/*chain=*/nullptr, "", CreateMockableWalletDatabase());
    {
        LOCK(compact_wallet.cs_wallet);
        compact_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        compact_wallet.SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
        FlatSigningProvider provider;
        std::string error;
        auto descs{Parse(multipath_descriptor, provider, error, /*require_checksum=*/false)};
        BOOST_REQUIRE_EQUAL(descs.size(), 2);
        bool internal{false};
        for (auto& desc : descs) {
            WalletDescriptor w_desc(std::move(desc), /*creation_time=*/0, /*range_start=*/0, /*range_end=*/10, /*next_index=*/0);
            BOOST_REQUIRE(compact_wallet.AddWalletDescriptor(w_desc, provider, "", internal));
            internal = true;
        }
    }
    std::shared_ptr<CWallet> compact_wallet_ptr{&compact_wallet, [](CWallet*) {}};
    auto compact_interface{interfaces::MakeWallet(context, compact_wallet_ptr)};
    auto compact_backup{compact_interface->createEncryptedDescriptorBackup(std::nullopt, /*compact=*/true)};
    BOOST_REQUIRE_MESSAGE(compact_backup, util::ErrorString(compact_backup).original);

    // Compact backups skip decoy padding, so only the real secret remains
    auto compact_metadata{CWallet::GetEncryptedBackupMetadata(*compact_backup)};
    BOOST_REQUIRE_MESSAGE(compact_metadata, util::ErrorString(compact_metadata).original);
    BOOST_CHECK_EQUAL(compact_metadata->individual_secret_count, 1);

    auto compact_decoded{DecodeEncryptedBackupBase64(*compact_backup)};
    BOOST_REQUIRE_MESSAGE(compact_decoded, util::ErrorString(compact_decoded).original);
    auto compact_plaintext{DecryptBackupWithDescriptor(*compact_decoded, multipath_descriptor)};
    BOOST_REQUIRE_MESSAGE(compact_plaintext, util::ErrorString(compact_plaintext).original);
    BOOST_CHECK_EQUAL(std::string(compact_plaintext->begin(), compact_plaintext->end()), multipath_descriptor);

    // Without an explicit xpub, the wallet derives candidate decryption keys
    // from its own HD keys at the common derivation paths.
    auto decrypted{wallet.DecryptEncryptedBackupBase64WithWalletKeys(*backup)};
    BOOST_REQUIRE_MESSAGE(decrypted, util::ErrorString(decrypted).original);
    const std::string decrypted_str{decrypted->begin(), decrypted->end()};
    BOOST_CHECK(decrypted_str.find("descriptor_sets") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(refuse_excluded_expressions_test)
{
    // A literal pubkey never contributes to the encryption key set, so its
    // holder could not decrypt the backup. BIP138 requires making the user
    // aware of each such expression; we refuse to create the backup, which
    // is stricter.
    const std::string literal_key{"03c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"};
    const std::string descriptor{"wsh(multi(1,[d34db33f/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*," + literal_key + "))"};

    EncryptedBackupContentType content;
    content.type = DataType::BIP_NUMBER;
    content.bip_number = BIP_DESCRIPTORS;

    std::vector<uint8_t> plaintext(descriptor.begin(), descriptor.end());
    auto backup_result = CreateEncryptedBackup(descriptor, plaintext, content, {});
    BOOST_REQUIRE(!backup_result);
    BOOST_CHECK_MESSAGE(util::ErrorString(backup_result).original.find(literal_key) != std::string::npos,
        "Error message should name the excluded expression: " << util::ErrorString(backup_result).original);

    // An allowed occurrence must not hide a bare occurrence of the same xpub.
    // A spend would reveal the root key and allow anyone to decrypt the backup.
    const std::string xpub{"tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba"};
    for (const std::string& reused_descriptor : {
             "wsh(or_i(pk(" + xpub + "/0/*),pk(" + xpub + ")))",
             "wsh(or_i(pk([d34db33f]" + xpub + "),pk([d34db33f]" + xpub + "/0/*)))",
         }) {
        const std::vector<uint8_t> reused_plaintext(reused_descriptor.begin(), reused_descriptor.end());
        const auto reused_result{CreateEncryptedBackup(reused_descriptor, reused_plaintext, content, {})};
        BOOST_REQUIRE(!reused_result);
        BOOST_CHECK_MESSAGE(util::ErrorString(reused_result).original.find(xpub) != std::string::npos,
            "Error message should name the bare xpub: " << util::ErrorString(reused_result).original);
    }

    // The NUMS point identifies no cosigner, so it does not trigger a refusal.
    const std::string nums_descriptor{"tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,pk([d34db33f/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*))"};
    std::vector<uint8_t> nums_plaintext(nums_descriptor.begin(), nums_descriptor.end());
    auto nums_result = CreateEncryptedBackup(nums_descriptor, nums_plaintext, content, {});
    BOOST_CHECK_MESSAGE(nums_result, util::ErrorString(nums_result).original);
}

BOOST_AUTO_TEST_CASE(wrong_key_decryption_test)
{
    // Test that decryption fails with wrong key
    // Use testnet tpub keys since we're running on RegTest
    std::string descriptor1 = "wpkh([11111111/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*)";
    std::string descriptor2 = "wpkh([22222222/84h/1h/0h]tpubDCBEcmVKbfC9KfdydyLbJ2gfNL88grZu1XcWSW9ytTM6fitvaRmVyr8Ddf7SjZ2ZfMx9RicjYAXhuh3fmLiVLPodPEqnQQURUfrBKiiVZc8/0/*)";

    EncryptedBackupContentType content;
    content.type = DataType::BIP_NUMBER;
    content.bip_number = BIP_DESCRIPTORS;

    std::vector<uint8_t> plaintext(descriptor1.begin(), descriptor1.end());

    // Create backup with descriptor1
    auto backup_result = CreateEncryptedBackup(descriptor1, plaintext, content, {});
    BOOST_REQUIRE_MESSAGE(backup_result, util::ErrorString(backup_result).original);

    // Try to decrypt with descriptor2 - should fail
    auto decrypted = DecryptBackupWithDescriptor(*backup_result, descriptor2);
    BOOST_CHECK_MESSAGE(!decrypted, "Decryption should fail with wrong key");
}

static const std::string BACKUP_TEST_XPUB{"tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba"};
static const std::string BACKUP_TEST_DESCRIPTOR{"wpkh(" + BACKUP_TEST_XPUB + "/<0;1>/*)"};

static EncryptedBackup EncryptTestPayload(std::span<const uint8_t> payload)
{
    auto keys{ExtractKeysFromDescriptor(BACKUP_TEST_DESCRIPTOR)};
    BOOST_REQUIRE(keys);
    const auto secret{ComputeDecryptionSecret(*keys)};
    EncryptedBackup backup;
    backup.individual_secrets = ComputeAllIndividualSecrets(secret, *keys);
    backup.nonce.fill(0);
    backup.nonce[0] = 1;
    backup.ciphertext.resize(payload.size() + AEADChaCha20Poly1305::EXPANSION);
    AEADChaCha20Poly1305 aead{MakeByteSpan(secret)};
    aead.Encrypt(MakeByteSpan(payload), {}, ReadAEADNonce(backup.nonce), MakeWritableByteSpan(backup.ciphertext));
    return backup;
}

BOOST_AUTO_TEST_CASE(payload_validation_test)
{
    const auto keys{ExtractKeysFromDescriptor(BACKUP_TEST_DESCRIPTOR)};
    BOOST_REQUIRE(keys);
    // Validate string content even when only looking for BIP380 items.
    const EncryptedBackupContentType string_type{.type = DataType::STRING, .bip_number = 0, .payload = {}};
    for (const auto& [hex, valid] : std::vector<std::pair<std::string, bool>>{
             {"00", true}, {"61c2a2e282acf09f92a97a", true}, {"eda080", false}}) {
        const auto text{ParseHex(hex)};
        const auto created{CreateEncryptedBackup(BACKUP_TEST_DESCRIPTOR, text, string_type, {})};
        BOOST_CHECK_EQUAL(bool(created), valid);
        std::vector<uint8_t> payload{3, 0, static_cast<uint8_t>(text.size())};
        payload.insert(payload.end(), text.begin(), text.end());
        const auto backup{EncryptTestPayload(payload)};
        BOOST_CHECK_EQUAL(DecryptBackupContentsWithKey(backup, keys->front()).has_value(), valid);
    }
    // Empty payloads, padding-only payloads, missing lengths, truncated content,
    // and unknown mandatory types must all fail after successful authentication.
    for (const std::string hex : {"", "00", "000102", "0300", "03000261", "800000", "040261"}) {
        BOOST_CHECK(!DecryptBackupContentsWithKey(EncryptTestPayload(ParseHex(hex)), keys->front()));
    }
    // Unknown optional content is skipped, and arbitrary bytes after 0x00 are padding.
    const auto optional{EncryptTestPayload(ParseHex("0401aa01bb0300016100ff80"))};
    auto contents{DecryptBackupContentsWithKey(optional, keys->front())};
    BOOST_REQUIRE(contents);
    BOOST_REQUIRE_EQUAL(contents->size(), 1);
    BOOST_CHECK_EQUAL(HexStr(contents->front()), "61");
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet

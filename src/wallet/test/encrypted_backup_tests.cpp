// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/encrypted_backup.h>

#include <test/data/bip138_keys_types.json.h>
#include <test/data/bip138_encryption_secret.json.h>

#include <test/util/json.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>
#include <univalue.h>

#include <algorithm>
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

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet

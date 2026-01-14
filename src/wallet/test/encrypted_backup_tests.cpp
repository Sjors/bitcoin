// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/encrypted_backup.h>

#include <test/data/bip138_keys_types.json.h>

#include <test/util/json.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>
#include <univalue.h>

#include <cstring>

namespace wallet {

// Use RegTest chain type so tpub keys (testnet prefixes) can be parsed
struct EncryptedBackupTestingSetup : public BasicTestingSetup {
    EncryptedBackupTestingSetup() : BasicTestingSetup(ChainType::REGTEST) {}
};

BOOST_FIXTURE_TEST_SUITE(encrypted_backup_tests, EncryptedBackupTestingSetup)

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

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet

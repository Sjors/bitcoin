// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/encrypted_backup.h>

#include <test/data/bip138_recipient_keys.json.h>

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

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet

// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/encryptedbackup.h>

#include <test/data/bip_encrypted_backup_keys_types.json.h>

#include <base58.h>
#include <key_io.h>
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

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet

// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/util.h>
#include <wallet/wallet.h>
#include <test/util/common.h>
#include <test/util/logging.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace wallet {

BOOST_AUTO_TEST_SUITE(walletload_tests)

class DummyDescriptor final : public Descriptor {
private:
    std::string desc;
public:
    explicit DummyDescriptor(const std::string& descriptor) : desc(descriptor) {};
    ~DummyDescriptor() = default;

    std::string ToString(bool compat_format) const override { return desc; }
    std::optional<OutputType> GetOutputType() const override { return OutputType::UNKNOWN; }

    bool IsRange() const override { return false; }
    bool IsSolvable() const override { return false; }
    bool IsSingleType() const override { return true; }
    bool HavePrivateKeys(const SigningProvider&) const override { return false; }
    bool ToPrivateString(const SigningProvider& provider, std::string& out) const override { return false; }
    bool ToNormalizedString(const SigningProvider& provider, std::string& out, const DescriptorCache* cache = nullptr) const override { return false; }
    bool Expand(int pos, const SigningProvider& provider, std::vector<CScript>& output_scripts, FlatSigningProvider& out, DescriptorCache* write_cache = nullptr) const override { return false; };
    bool ExpandFromCache(int pos, const DescriptorCache& read_cache, std::vector<CScript>& output_scripts, FlatSigningProvider& out) const override { return false; }
    void ExpandPrivate(int pos, const SigningProvider& provider, FlatSigningProvider& out) const override {}
    std::optional<int64_t> ScriptSize() const override { return {}; }
    std::optional<int64_t> MaxSatisfactionWeight(bool) const override { return {}; }
    std::optional<int64_t> MaxSatisfactionElems() const override { return {}; }
    void GetPubKeys(std::set<CPubKey>& pubkeys, std::set<CExtPubKey>& ext_pubs) const override {}
    bool HasScripts() const override { return true; }
    std::vector<std::string> Warnings() const override { return {}; }
    uint32_t GetMaxKeyExpr() const override { return 0; }
    size_t GetKeyCount() const override { return 0; }
    bool CanSelfExpand() const final { return false; }
};

BOOST_FIXTURE_TEST_CASE(wallet_load_descriptors, TestingSetup)
{
    bilingual_str _error;
    std::vector<bilingual_str> _warnings;
    std::unique_ptr<WalletDatabase> database = CreateMockableWalletDatabase();
    {
        // Write unknown active descriptor
        WalletBatch batch(*database);
        std::string unknown_desc = "trx(tpubD6NzVbkrYhZ4Y4S7m6Y5s9GD8FqEMBy56AGphZXuagajudVZEnYyBahZMgHNCTJc2at82YX6s8JiL1Lohu5A3v1Ur76qguNH4QVQ7qYrBQx/86'/1'/0'/0/*)#8pn8tzdt";
        WalletDescriptor wallet_descriptor(std::make_shared<DummyDescriptor>(unknown_desc), 0, 0, 0, 0);
        BOOST_CHECK(batch.WriteDescriptor(uint256(), wallet_descriptor));
        BOOST_CHECK(batch.WriteActiveScriptPubKeyMan(static_cast<uint8_t>(OutputType::UNKNOWN), uint256(), false));
    }

    {
        // Now try to load the wallet and verify the error.
        const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
        BOOST_CHECK_EQUAL(wallet->PopulateWalletFromDB(_error, _warnings), DBErrors::UNKNOWN_DESCRIPTOR);
    }

    // Test 2
    // Now write a valid descriptor with an invalid ID.
    // As the software produces another ID for the descriptor, the loading process must be aborted.
    database = CreateMockableWalletDatabase();

    // Verify the error
    bool found = false;
    DebugLogHelper logHelper("The descriptor ID calculated by the wallet differs from the one in DB", [&](const std::string* s) {
        found = true;
        return false;
    });

    {
        // Write valid descriptor with invalid ID
        WalletBatch batch(*database);
        std::string desc = "wpkh([d34db33f/84h/0h/0h]xpub6DJ2dNUysrn5Vt36jH2KLBT2i1auw1tTSSomg8PhqNiUtx8QX2SvC9nrHu81fT41fvDUnhMjEzQgXnQjKEu3oaqMSzhSrHMxyyoEAmUHQbY/0/*)#cjjspncu";
        WalletDescriptor wallet_descriptor(std::make_shared<DummyDescriptor>(desc), 0, 0, 0, 0);
        BOOST_CHECK(batch.WriteDescriptor(uint256::ONE, wallet_descriptor));
    }

    {
        // Now try to load the wallet and verify the error.
        const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
        BOOST_CHECK_EQUAL(wallet->PopulateWalletFromDB(_error, _warnings), DBErrors::CORRUPT);
        BOOST_CHECK(found); // The error must be logged
    }
}

BOOST_FIXTURE_TEST_CASE(wallet_load_multipath, TestingSetup)
{
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    const std::string xpub{"xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"};

    const auto make_desc{[](const std::string& desc_str) {
        FlatSigningProvider keys;
        std::string parse_error;
        auto descs = Parse(desc_str, keys, parse_error);
        BOOST_REQUIRE_MESSAGE(!descs.empty(), desc_str + ": " + parse_error);
        // Use an empty range so that loading does not require cache records
        if (descs.size() == 1) return WalletDescriptor(std::move(descs.at(0)), 0, 0, 0, 0);
        return WalletDescriptor(std::make_shared<MultipathDescriptor>(std::move(descs)), 0, 0, 0, 0);
    }};
    const auto load_result{[&](uint64_t flags, const std::string& desc_str) {
        std::unique_ptr<WalletDatabase> database = CreateMockableWalletDatabase();
        {
            WalletBatch batch(*database);
            BOOST_CHECK(batch.WriteWalletFlags(flags));
            WalletDescriptor desc = make_desc(desc_str);
            BOOST_CHECK(batch.WriteDescriptor(desc.id, desc));
        }
        const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
        return wallet->PopulateWalletFromDB(error, warnings);
    }};

    // A multipath record does not load in a wallet without the multipath flag
    BOOST_CHECK_EQUAL(load_result(WALLET_FLAG_DESCRIPTORS, "wpkh(" + xpub + "/<0;1>/*)"), DBErrors::UNKNOWN_DESCRIPTOR);

    // A single path record with scripts does not load in a multipath wallet
    BOOST_CHECK_EQUAL(load_result(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_MULTIPATH_DESCRIPTORS, "wpkh(" + xpub + "/0/*)"), DBErrors::UNKNOWN_DESCRIPTOR);

    // The record format supports any number of paths, but this version only
    // loads a receive and change pair, so wallets written by a hypothetical
    // future version with more paths are refused rather than misinterpreted
    BOOST_CHECK_EQUAL(load_result(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_MULTIPATH_DESCRIPTORS, "wpkh(" + xpub + "/<0;1;2>/*)"), DBErrors::UNKNOWN_DESCRIPTOR);

    // A receive and change pair loads in a multipath wallet
    BOOST_CHECK_EQUAL(load_result(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_MULTIPATH_DESCRIPTORS, "wpkh(" + xpub + "/<0;1>/*)"), DBErrors::LOAD_OK);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet

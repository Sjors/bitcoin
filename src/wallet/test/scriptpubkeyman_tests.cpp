// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <key_io.h>
#include <test/util/common.h>
#include <test/util/setup_common.h>
#include <script/solver.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>
#include <wallet/test/util.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(scriptpubkeyman_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(DescriptorScriptPubKeyManTests)
{
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    CWallet keystore(chain.get(), "", CreateMockableWalletDatabase());
    auto key_scriptpath = GenerateRandomKey();

    // Verify that a SigningProvider for a pubkey is only returned if its corresponding private key is available
    auto key_internal = GenerateRandomKey();
    std::string desc_str = "tr(" + EncodeSecret(key_internal) + ",pk(" + HexStr(key_scriptpath.GetPubKey()) + "))";
    auto spk_man1 = CreateDescriptor(keystore, desc_str, true);
    BOOST_CHECK(spk_man1 != nullptr);
    auto signprov_keypath_spendable = spk_man1->GetSigningProvider(key_internal.GetPubKey());
    BOOST_CHECK(signprov_keypath_spendable != nullptr);

    desc_str = "tr(" + HexStr(XOnlyPubKey::NUMS_H) + ",pk(" + HexStr(key_scriptpath.GetPubKey()) + "))";
    auto spk_man2 = CreateDescriptor(keystore, desc_str, true);
    BOOST_CHECK(spk_man2 != nullptr);
    auto signprov_keypath_nums_h = spk_man2->GetSigningProvider(XOnlyPubKey::NUMS_H.GetEvenCorrespondingCPubKey());
    BOOST_CHECK(signprov_keypath_nums_h == nullptr);
}

BOOST_AUTO_TEST_CASE(desc_spkm_topup_fail)
{
    // Attempting to construct a DescriptorSPKM that cannot be topped up (hardened derivation without private keys)
    // should throw even though it is valid and can be parsed
    CExtKey extkey;
    extkey.SetSeed(std::array<std::byte, 32>{});
    CWallet keystore(m_node.chain.get(), "", CreateMockableWalletDatabase());
    BOOST_CHECK_EXCEPTION(
        CreateDescriptor(keystore, "wpkh(" + EncodeExtPubKey(extkey.Neuter()) + "/*h)", /*success=*/true),
        std::runtime_error, HasReason("Could not top up scriptPubKeys"));
}

BOOST_AUTO_TEST_CASE(derive_multipath_descriptor)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    LOCK(wallet.cs_wallet);
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);

    const std::string xpub_a{"xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"};
    const std::string xpub_b{"xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"};

    // Parse a multipath descriptor and import both expanded descriptors.
    auto import_multipath = [&](const std::string& desc_str) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet) {
        FlatSigningProvider keys;
        std::string error;
        auto parsed_descs = Parse(desc_str, keys, error, /*require_checksum=*/false);
        BOOST_REQUIRE_MESSAGE(parsed_descs.size() == 2, desc_str + ": " + error);
        std::vector<DescriptorScriptPubKeyMan*> spkms;
        for (auto& desc : parsed_descs) {
            WalletDescriptor w_desc(std::move(desc), /*creation_time=*/1, /*range_start=*/0, /*range_end=*/1, /*next_index=*/0);
            auto spkm_res{wallet.AddWalletDescriptor(w_desc, keys, /*label=*/"", /*internal=*/false)};
            BOOST_REQUIRE_MESSAGE(spkm_res, util::ErrorString(spkm_res).original);
            spkms.push_back(&spkm_res->get());
        }
        return std::pair{spkms.at(0), spkms.at(1)};
    };

    // Roundtrip multipath descriptors through their expanded receive and change
    // pair. Coverage of the various descriptor shapes lives in descriptor_tests.
    const std::vector<std::string> multipath_descs{
        "wsh(sortedmulti(2," + xpub_a + "/<0;1>/*," + xpub_b + "/<0;1>/*))",
        "tr(musig(" + xpub_a + "," + xpub_b + ")/<0;1>/*)",
        "wpkh(" + xpub_a + "/<2;3>/*)",
    };
    for (const std::string& multipath_desc : multipath_descs) {
        auto [receive, change] = import_multipath(multipath_desc);
        auto res{DeriveMultipathDescriptor(*receive, *change)};
        BOOST_REQUIRE_MESSAGE(res, util::ErrorString(res).original);
        BOOST_CHECK_EQUAL(*res, multipath_desc);
    }

    auto [multi_receive, multi_change] = import_multipath("wsh(multi(2," + xpub_a + "/<0;1>/*," + xpub_b + "/<0;1>/*))");
    auto [other_receive, other_change] = import_multipath("wsh(multi(1," + xpub_a + "/<0;1>/*," + xpub_b + "/<0;1>/*))");

    // Descriptors derived from different multipath descriptors cannot be combined
    auto mismatch{DeriveMultipathDescriptor(*multi_receive, *other_change)};
    BOOST_REQUIRE(!mismatch);
    BOOST_CHECK(util::ErrorString(mismatch).original.starts_with("Receive and change descriptors are not derived from the same multipath descriptor"));

    // The receive descriptor must come first
    auto swapped{DeriveMultipathDescriptor(*multi_change, *multi_receive)};
    BOOST_REQUIRE(!swapped);
    BOOST_CHECK(util::ErrorString(swapped).original.starts_with("Receive and change descriptors are not derived from the same multipath descriptor"));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet

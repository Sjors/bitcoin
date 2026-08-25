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

BOOST_AUTO_TEST_CASE(desc_spkm_multipath)
{
    CWallet keystore(m_node.chain.get(), "", CreateMockableWalletDatabase());
    keystore.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    keystore.SetWalletFlag(WALLET_FLAG_MULTIPATH_DESCRIPTORS);

    CExtKey master_key;
    master_key.SetSeed(std::array<std::byte, 32>{});
    const std::string desc_str = "wpkh(" + EncodeExtKey(master_key) + "/84h/<0;1>/*)";

    FlatSigningProvider keys;
    std::string error;
    auto parsed_descs = Parse(desc_str, keys, error);
    BOOST_REQUIRE_EQUAL(parsed_descs.size(), 2U);
    WalletDescriptor w_desc(std::make_shared<MultipathDescriptor>(std::move(parsed_descs)), /*creation_time=*/1, /*range_start=*/0, /*range_end=*/10, /*next_index=*/0);

    LOCK(keystore.cs_wallet);
    DescriptorScriptPubKeyMan& spkm = Assert(keystore.AddWalletDescriptor(w_desc, keys, /*label=*/"", /*internal=*/false))->get();
    BOOST_CHECK(spkm.IsMultipathDescriptor());

    // Receive and change addresses are handed out from separate chains with independent counters
    const CTxDestination receive1 = *Assert(spkm.GetNewDestination(OutputType::BECH32, /*internal=*/false));
    const CTxDestination change1 = *Assert(spkm.GetNewDestination(OutputType::BECH32, /*internal=*/true));
    const CTxDestination receive2 = *Assert(spkm.GetNewDestination(OutputType::BECH32, /*internal=*/false));
    BOOST_CHECK(receive1 != change1);
    BOOST_CHECK(receive1 != receive2);
    {
        LOCK(spkm.cs_desc_man);
        BOOST_CHECK_EQUAL(spkm.GetWalletDescriptor().GetNext(/*path=*/0), 2);
        BOOST_CHECK_EQUAL(spkm.GetWalletDescriptor().GetNext(/*path=*/1), 1);
    }
    // The receive chain handed out one address more than the change chain
    BOOST_CHECK_EQUAL(spkm.GetKeyPoolSize(/*internal=*/false) + 1, spkm.GetKeyPoolSize(/*internal=*/true));
    BOOST_CHECK_EQUAL(spkm.GetKeyPoolSize(), spkm.GetKeyPoolSize(/*internal=*/false) + spkm.GetKeyPoolSize(/*internal=*/true));

    // The addresses match the expansions of the corresponding path
    FlatSigningProvider expand_keys;
    auto expand_descs = Parse(desc_str, expand_keys, error);
    const auto expect_script{[&](size_t path, int32_t index, const CTxDestination& dest) {
        std::vector<CScript> spks;
        FlatSigningProvider out;
        BOOST_REQUIRE(expand_descs.at(path)->Expand(index, expand_keys, spks, out));
        BOOST_CHECK(GetScriptForDestination(dest) == spks.at(0));
    }};
    expect_script(0, 0, receive1);
    expect_script(0, 1, receive2);
    expect_script(1, 0, change1);

    // Scripts of both chains are recognized and solvable
    for (const CTxDestination& dest : {receive1, change1, receive2}) {
        const CScript script = GetScriptForDestination(dest);
        BOOST_CHECK(spkm.IsMine(script));
        BOOST_CHECK(spkm.GetSolvingProvider(script) != nullptr);
    }
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

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet

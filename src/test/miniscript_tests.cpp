// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include <string>

#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

#include <hash.h>
#include <pubkey.h>
#include <uint256.h>
#include <crypto/sha256.h>
#include <script/miniscript.h>

namespace {

/** TestData groups various kinds of precomputed data necessary in this test. */
struct TestData {
    //! The only public keys used in this test.
    std::vector<CPubKey> pubkeys;
    //! A map from the public keys to their CKeyIDs (faster than hashing every time).
    std::map<CPubKey, CKeyID> pkhashes;

    // Various precomputed hashes
    std::vector<std::vector<unsigned char>> sha256;
    std::vector<std::vector<unsigned char>> hash160;

    TestData()
    {
        // We generate 255 public keys and 255 hashes of each type.
        for (int i = 1; i <= 255; ++i) {
            // This 32-byte array functions as both private key data and hash preimage (31 zero bytes plus any nonzero byte).
            unsigned char keydata[32] = {0};
            keydata[31] = i;

            // Compute CPubkey and CKeyID
            CKey key;
            key.Set(keydata, keydata + 32, true);
            CPubKey pubkey = key.GetPubKey();
            CKeyID keyid = pubkey.GetID();
            pubkeys.push_back(pubkey);
            pkhashes.emplace(pubkey, keyid);

            // Compute various hashes
            std::vector<unsigned char> hash;
            hash.resize(32);
            CSHA256().Write(keydata, 32).Finalize(hash.data());
            sha256.push_back(hash);
            hash.resize(20);
            CHash160().Write(keydata).Finalize(hash);
            hash160.push_back(hash);
        }
    }
};

//! Global TestData object
std::unique_ptr<const TestData> g_testdata;

/** A class encapsulating conversion routing for CPubKey. */
struct KeyConverter {
    typedef CPubKey Key;

    //! Convert a public key to bytes.
    std::vector<unsigned char> ToPKBytes(const CPubKey& key) const { return {key.begin(), key.end()}; }

    //! Convert a public key to its Hash160 bytes (precomputed).
    std::vector<unsigned char> ToPKHBytes(const CPubKey& key) const
    {
        auto it = g_testdata->pkhashes.find(key);
        assert(it != g_testdata->pkhashes.end());
        return {it->second.begin(), it->second.end()};
    }

    //! Parse a public key from a range of hex characters.
    template<typename I>
    bool FromString(I first, I last, CPubKey& key) const {
        auto bytes = ParseHex(std::string(first, last));
        key.Set(bytes.begin(), bytes.end());
        return key.IsValid();
    }
};

//! Singleton instance of KeyConverter.
const KeyConverter CONVERTER{};

// Helper types and functions that use miniscript instantiated for CPubKey.
using NodeType = miniscript::NodeType;
using NodeRef = miniscript::NodeRef<CPubKey>;
template<typename... Args> NodeRef MakeNodeRef(Args&&... args) { return miniscript::MakeNodeRef<CPubKey>(std::forward<Args>(args)...); }
using miniscript::operator"" _mst;

enum TestMode : int {
    TESTMODE_INVALID = 0,
    TESTMODE_VALID = 1,
    TESTMODE_NONMAL = 2,
    TESTMODE_NEEDSIG = 4,
    TESTMODE_TIMELOCKMIX = 8
};

void Test(const std::string& ms, const std::string& hexscript, int mode)
{
    auto node = miniscript::FromString(ms, CONVERTER);
    if (mode == TESTMODE_INVALID) {
        BOOST_CHECK_MESSAGE(!node || !node->IsValid(), "Unexpectedly valid: " + ms);
    } else {
        BOOST_CHECK_MESSAGE(node, "Unparseable: " + ms);
        BOOST_CHECK_MESSAGE(node->IsValid(), "Invalid: " + ms);
        BOOST_CHECK_MESSAGE(node->IsValidTopLevel(), "Invalid top level: " + ms);
        auto computed_script = node->ToScript(CONVERTER);
        BOOST_CHECK_MESSAGE(node->ScriptSize() == computed_script.size(), "Script size mismatch: " + ms);
        if (hexscript != "?") BOOST_CHECK_MESSAGE(HexStr(computed_script) == hexscript, "Script mismatch: " + ms + " (" + HexStr(computed_script) + " vs " + hexscript + ")");
        BOOST_CHECK_MESSAGE(node->IsNonMalleable() == !!(mode & TESTMODE_NONMAL), "Malleability mismatch: " + ms);
        BOOST_CHECK_MESSAGE(node->NeedsSignature() == !!(mode & TESTMODE_NEEDSIG), "Signature necessity mismatch: " + ms);
        BOOST_CHECK_MESSAGE((node->GetType() << "k"_mst) == !(mode & TESTMODE_TIMELOCKMIX), "Timelock mix mismatch: " + ms);
    }

}
} // namespace

BOOST_FIXTURE_TEST_SUITE(miniscript_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(fixed_tests)
{
    g_testdata.reset(new TestData());

    // Validity rules
    Test("andor(0,1,1)", "?", TESTMODE_VALID | TESTMODE_NONMAL); // andor(Bdu,B,B): valid
    Test("andor(1,1,1)", "?", TESTMODE_INVALID); // andor(Bu,B,B): X must be d
    Test("andor(or_i(0,after(1)),1,1)", "?", TESTMODE_INVALID); // andor(Bd,B,B): X must be u
    Test("c:andor(0,pk_k(03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7),pk_k(036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00))", "?", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG); // andor(Bdu,K,K): valid
    Test("and_v(1,1)", "?", TESTMODE_INVALID); // and_v(B,B): X must be V
    Test("and_v(pk_k(02352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5),1)", "?", TESTMODE_INVALID); // and_v(K,B): X must be V
    Test("and_b(1,1)", "?", TESTMODE_INVALID); // and_b(B,B): Y must W
    Test("and_b(pk_k(025601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc),a:1)", "?", TESTMODE_INVALID); // and_b(K,W): X must be B
    Test("or_b(0,0)", "?", TESTMODE_INVALID); // or_b(Bd,Bd): Y must W
    Test("or_b(pk_k(025601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc),a:0)", "?", TESTMODE_INVALID); // or_b(Kd,Wd): X must be B
    Test("or_d(0,1)", "?", TESTMODE_VALID | TESTMODE_NONMAL); // or_d(Bdu,B): valid
    Test("or_d(1,1)", "?", TESTMODE_INVALID); // or_d(Bu,B): X must be d
    Test("or_d(or_i(0,after(1)),1)", "?", TESTMODE_INVALID); // or_d(Bd,B): X must be u
    Test("or_i(1,1)", "?", TESTMODE_VALID); // or_i(B,B): valid
    Test("c:or_i(pk_k(03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7),pk_k(036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00))", "?", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG); // or_i(K,K): valid
    Test("pk(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65)", "2103d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65ac", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG); // alias to c:pk_k
    Test("pkh(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65)", "76a914fcd35ddacad9f2d5be5e464639441c6065e6955d88ac", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG); // alias to c:pk_h


    // Randomly generated test set that covers the majority of type and node type combinations
    Test("or_d(c:pk_h(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13),andor(c:pk_k(024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),older(2016),after(1567547623)))", "76a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac736421024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97ac6404e7e06e5db16702e007b26868", TESTMODE_VALID | TESTMODE_NONMAL);
    Test("c:or_i(andor(c:pk_h(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),pk_h(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01),pk_h(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)),pk_k(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e))", "6376a914fcd35ddacad9f2d5be5e464639441c6065e6955d88ac6476a91406afd46bcdfd22ef94ac122aa11f241244a37ecc886776a9149652d86bedf43ad264362e6e6eba6eb7645081278868672102d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e68ac", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG);

    // Timelock tests
    Test("after(100)", "?", TESTMODE_VALID | TESTMODE_NONMAL); // only heightlock
    Test("after(1000000000)", "?", TESTMODE_VALID | TESTMODE_NONMAL); // only timelock

    g_testdata.reset();
}

BOOST_AUTO_TEST_SUITE_END()

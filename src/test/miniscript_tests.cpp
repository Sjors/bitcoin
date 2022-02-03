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
    Test("l:older(1)", "?", TESTMODE_VALID | TESTMODE_NONMAL); // older(1): valid
    Test("l:older(0)", "?", TESTMODE_INVALID); // older(0): k must be at least 1
    Test("l:older(2147483647)", "?", TESTMODE_VALID | TESTMODE_NONMAL); // older(2147483647): valid
    Test("l:older(2147483648)", "?", TESTMODE_INVALID); // older(2147483648): k must be below 2^31
    Test("u:after(1)", "?", TESTMODE_VALID | TESTMODE_NONMAL); // after(1): valid
    Test("u:after(0)", "?", TESTMODE_INVALID); // after(0): k must be at least 1
    Test("u:after(2147483647)", "?", TESTMODE_VALID | TESTMODE_NONMAL); // after(2147483647): valid
    Test("u:after(2147483648)", "?", TESTMODE_INVALID); // after(2147483648): k must be below 2^31
    Test("andor(0,1,1)", "?", TESTMODE_VALID | TESTMODE_NONMAL); // andor(Bdu,B,B): valid
    Test("andor(a:0,1,1)", "?", TESTMODE_INVALID); // andor(Wdu,B,B): X must be B
    Test("andor(0,a:1,a:1)", "?", TESTMODE_INVALID); // andor(Bdu,W,W): Y and Z must be B/V/K
    Test("andor(1,1,1)", "?", TESTMODE_INVALID); // andor(Bu,B,B): X must be d
    Test("andor(n:or_i(0,after(1)),1,1)", "?", TESTMODE_VALID); // andor(Bdu,B,B): valid
    Test("andor(or_i(0,after(1)),1,1)", "?", TESTMODE_INVALID); // andor(Bd,B,B): X must be u
    Test("c:andor(0,pk_k(03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7),pk_k(036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00))", "?", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG); // andor(Bdu,K,K): valid
    Test("t:andor(0,v:1,v:1)", "?", TESTMODE_VALID | TESTMODE_NONMAL); // andor(Bdu,V,V): valid
    Test("and_v(v:1,1)", "?", TESTMODE_VALID | TESTMODE_NONMAL); // and_v(V,B): valid
    Test("t:and_v(v:1,v:1)", "?", TESTMODE_VALID | TESTMODE_NONMAL); // and_v(V,V): valid
    Test("c:and_v(v:1,pk_k(036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00))", "?", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG); // and_v(V,K): valid
    Test("and_v(1,1)", "?", TESTMODE_INVALID); // and_v(B,B): X must be V
    Test("and_v(pk_k(02352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5),1)", "?", TESTMODE_INVALID); // and_v(K,B): X must be V
    Test("and_v(v:1,a:1)", "?", TESTMODE_INVALID); // and_v(K,W): Y must be B/V/K
    Test("and_b(1,a:1)", "?", TESTMODE_VALID | TESTMODE_NONMAL); // and_b(B,W): valid
    Test("and_b(1,1)", "?", TESTMODE_INVALID); // and_b(B,B): Y must W
    Test("and_b(v:1,a:1)", "?", TESTMODE_INVALID); // and_b(V,W): X must be B
    Test("and_b(a:1,a:1)", "?", TESTMODE_INVALID); // and_b(W,W): X must be B
    Test("and_b(pk_k(025601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc),a:1)", "?", TESTMODE_INVALID); // and_b(K,W): X must be B
    Test("or_b(0,a:0)", "?", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG); // or_b(Bd,Wd): valid
    Test("or_b(1,a:0)", "?", TESTMODE_INVALID); // or_b(B,Wd): X must be d
    Test("or_b(0,a:1)", "?", TESTMODE_INVALID); // or_b(Bd,W): Y must be d
    Test("or_b(0,0)", "?", TESTMODE_INVALID); // or_b(Bd,Bd): Y must W
    Test("or_b(v:0,a:0)", "?", TESTMODE_INVALID); // or_b(V,Wd): X must be B
    Test("or_b(a:0,a:0)", "?", TESTMODE_INVALID); // or_b(Wd,Wd): X must be B
    Test("or_b(pk_k(025601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc),a:0)", "?", TESTMODE_INVALID); // or_b(Kd,Wd): X must be B
    Test("t:or_c(0,v:1)", "?", TESTMODE_VALID | TESTMODE_NONMAL); // or_c(Bdu,V): valid
    Test("t:or_c(a:0,v:1)", "?", TESTMODE_INVALID); // or_c(Wdu,V): X must be B
    Test("t:or_c(1,v:1)", "?", TESTMODE_INVALID); // or_c(Bu,V): X must be d
    Test("t:or_c(n:or_i(0,after(1)),v:1)", "?", TESTMODE_VALID); // or_c(Bdu,V): valid
    Test("t:or_c(or_i(0,after(1)),v:1)", "?", TESTMODE_INVALID); // or_c(Bd,V): X must be u
    Test("t:or_c(0,1)", "?", TESTMODE_INVALID); // or_c(Bdu,B): Y must be V
    Test("or_d(0,1)", "?", TESTMODE_VALID | TESTMODE_NONMAL); // or_d(Bdu,B): valid
    Test("or_d(a:0,1)", "?", TESTMODE_INVALID); // or_d(Wdu,B): X must be B
    Test("or_d(1,1)", "?", TESTMODE_INVALID); // or_d(Bu,B): X must be d
    Test("or_d(n:or_i(0,after(1)),1)", "?", TESTMODE_VALID); // or_d(Bdu,B): valid
    Test("or_d(or_i(0,after(1)),1)", "?", TESTMODE_INVALID); // or_d(Bd,B): X must be u
    Test("or_d(0,v:1)", "?", TESTMODE_INVALID); // or_d(Bdu,V): Y must be B
    Test("or_i(1,1)", "?", TESTMODE_VALID); // or_i(B,B): valid
    Test("t:or_i(v:1,v:1)", "?", TESTMODE_VALID); // or_i(V,V): valid
    Test("c:or_i(pk_k(03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7),pk_k(036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00))", "?", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG); // or_i(K,K): valid
    Test("or_i(a:1,a:1)", "?", TESTMODE_INVALID); // or_i(W,W): X and Y must be B/V/K
    Test("or_b(l:after(100),al:after(1000000000))", "?", TESTMODE_VALID); // or_b(timelock, heighlock) valid
    Test("and_b(after(100),a:after(1000000000))", "?", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_TIMELOCKMIX); // and_b(timelock, heighlock) invalid
    Test("pk(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65)", "2103d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65ac", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG); // alias to c:pk_k
    Test("pkh(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65)", "76a914fcd35ddacad9f2d5be5e464639441c6065e6955d88ac", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG); // alias to c:pk_h


    // Randomly generated test set that covers the majority of type and node type combinations
    Test("lltvln:after(1231488000)", "6300676300676300670400046749b1926869516868", TESTMODE_VALID | TESTMODE_NONMAL);
    Test("uuj:and_v(v:multi(2,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a,025601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc),after(1231488000))", "6363829263522103d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a21025601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc52af0400046749b168670068670068", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG);
    Test("or_b(un:multi(2,03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729,024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),al:older(16))", "63522103daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee872921024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c9752ae926700686b63006760b2686c9b", TESTMODE_VALID);
    Test("j:and_v(vdv:after(1567547623),older(2016))", "829263766304e7e06e5db169686902e007b268", TESTMODE_VALID | TESTMODE_NONMAL);
    Test("or_d(multi(1,02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9),or_b(multi(3,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,032fa2104d6b38d11b0230010559879124e42ab8dfeff5ff29dc9cdadd4ecacc3f,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a),su:after(500000)))", "512102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f951ae73645321022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a0121032fa2104d6b38d11b0230010559879124e42ab8dfeff5ff29dc9cdadd4ecacc3f2103d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a53ae7c630320a107b16700689b68", TESTMODE_VALID | TESTMODE_NONMAL);
    Test("j:and_b(multi(2,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),s:or_i(older(1),older(4252898)))", "82926352210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179821024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c9752ae7c6351b26703e2e440b2689a68", TESTMODE_VALID | TESTMODE_NEEDSIG);
    Test("and_n(c:pk_k(03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729),and_b(l:older(4252898),a:older(16)))", "2103daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729ac64006763006703e2e440b2686b60b26c9a68", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG | TESTMODE_TIMELOCKMIX);
    Test("c:or_i(and_v(v:older(16),pk_h(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)),pk_h(026a245bf6dc698504c89a20cfded60853152b695336c28063b61c65cbd269e6b4))", "6360b26976a9149fc5dbe5efdce10374a4dd4053c93af540211718886776a9142fbd32c8dd59ee7c17e66cb6ebea7e9846c3040f8868ac", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG);
    Test("or_d(c:pk_h(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13),andor(c:pk_k(024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),older(2016),after(1567547623)))", "76a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac736421024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97ac6404e7e06e5db16702e007b26868", TESTMODE_VALID | TESTMODE_NONMAL);
    Test("c:or_i(andor(c:pk_h(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),pk_h(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01),pk_h(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)),pk_k(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e))", "6376a914fcd35ddacad9f2d5be5e464639441c6065e6955d88ac6476a91406afd46bcdfd22ef94ac122aa11f241244a37ecc886776a9149652d86bedf43ad264362e6e6eba6eb7645081278868672102d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e68ac", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG);

    // Timelock tests
    Test("after(100)", "?", TESTMODE_VALID | TESTMODE_NONMAL); // only heightlock
    Test("after(1000000000)", "?", TESTMODE_VALID | TESTMODE_NONMAL); // only timelock
    Test("or_b(l:after(100),al:after(1000000000))", "?", TESTMODE_VALID); // or_b(timelock, heighlock) valid
    Test("and_b(after(100),a:after(1000000000))", "?", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_TIMELOCKMIX); // and_b(timelock, heighlock) invalid

    g_testdata.reset();
}

BOOST_AUTO_TEST_SUITE_END()

// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>
#include <clientversion.h>
#include <script/descriptor.h>
#include <script/signingprovider.h>
#include <streams.h>
#include <uint256.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(walletdb_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(walletdb_readkeyvalue)
{
    /**
     * When ReadKeyValue() reads from either a "key" or "wkey" it first reads the DataStream into a
     * CPrivKey or CWalletKey respectively and then reads a hash of the pubkey and privkey into a uint256.
     * Wallets from 0.8 or before do not store the pubkey/privkey hash, trying to read the hash from old
     * wallets throws an exception, for backwards compatibility this read is wrapped in a try block to
     * silently fail. The test here makes sure the type of exception thrown from DataStream::read()
     * matches the type we expect, otherwise we need to update the "key"/"wkey" exception type caught.
     */
    DataStream ssValue{};
    uint256 dummy;
    BOOST_CHECK_THROW(ssValue >> dummy, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(walletdescriptor_multipath_roundtrip)
{
    const std::string xpub{"xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"};
    const std::string desc_str{"wpkh(" + xpub + "/<0;1>/*)"};

    FlatSigningProvider keys;
    std::string error;
    auto descs = Parse(desc_str, keys, error);
    BOOST_REQUIRE_EQUAL(descs.size(), 2U);
    WalletDescriptor w_desc(std::make_shared<MultipathDescriptor>(std::move(descs)), /*creation_time=*/123, /*range_start=*/0, /*range_end=*/10, /*next_index=*/3);
    // Make the per-path states differ
    w_desc.IncNext(/*path=*/1);
    w_desc.SetEnd(/*path=*/1, 20);

    DataStream s{};
    s << w_desc;
    WalletDescriptor loaded;
    s >> loaded;
    BOOST_CHECK(loaded.IsMultipath());
    BOOST_CHECK_EQUAL(loaded.NumPaths(), 2U);
    BOOST_CHECK(loaded.id == w_desc.id);
    BOOST_CHECK_EQUAL(loaded.creation_time, 123U);
    BOOST_CHECK_EQUAL(loaded.GetNext(0), 3);
    BOOST_CHECK_EQUAL(loaded.GetEnd(0), 10);
    BOOST_CHECK_EQUAL(loaded.GetNext(1), 4);
    BOOST_CHECK_EQUAL(loaded.GetEnd(1), 20);
    BOOST_CHECK_EQUAL(loaded.multipath->ToString(), w_desc.multipath->ToString());
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet

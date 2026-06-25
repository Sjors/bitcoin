// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <interfaces/wallet.h>
#include <test/util/setup_common.h>
#include <wallet/context.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

namespace wallet {

BOOST_FIXTURE_TEST_SUITE(wallet_interfaces_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(addhdkey)
{
    WalletContext context;
    context.args = &m_args;
    auto wallet = TestCreateWallet(context);
    auto interface = interfaces::MakeWallet(context, wallet);

    auto result = interface->addHDKey();
    BOOST_REQUIRE(result);
    BOOST_CHECK(result->pubkey.IsValid());
}

BOOST_AUTO_TEST_CASE(addhdkey_wallet_locked)
{
    WalletContext context;
    context.args = &m_args;
    auto wallet = TestCreateWallet(context);
    BOOST_REQUIRE(wallet->EncryptWallet("hunter2"));
    BOOST_REQUIRE(wallet->Lock());

    auto interface = interfaces::MakeWallet(context, wallet);
    auto result = interface->addHDKey();
    BOOST_REQUIRE(!result);
    BOOST_CHECK(result.error().code == WalletErrorCode::WALLET_UNLOCK_NEEDED);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet

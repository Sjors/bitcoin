// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/sockman.h>
#include <test/util/setup_common.h>
#include <util/translation.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(sockman_tests, SocketTestingSetup)

BOOST_AUTO_TEST_CASE(test_sockman)
{
    SockMan sockman;

    // This address won't actually get used because we stubbed CreateSock()
    const std::optional<CService> addr{Lookup("0.0.0.0", 0, false)};
    BOOST_REQUIRE(addr.has_value());
    bilingual_str strError;

    // Init state
    BOOST_REQUIRE_EQUAL(sockman.m_listen.size(), 0);
    // Bind to mock Listening Socket
    BOOST_REQUIRE(sockman.BindListenPort(addr.value(), strError));
    // We are bound and listening
    BOOST_REQUIRE_EQUAL(sockman.m_listen.size(), 1);
}

BOOST_AUTO_TEST_SUITE_END()

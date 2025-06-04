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
    const std::optional<CService> addr_bind{Lookup("0.0.0.0", 0, false)};
    BOOST_REQUIRE(addr_bind.has_value());
    bilingual_str strError;

    // Init state
    BOOST_REQUIRE_EQUAL(sockman.m_listen.size(), 0);
    // Bind to mock Listening Socket
    BOOST_REQUIRE(sockman.BindAndStartListening(addr_bind.value(), strError));
    // We are bound and listening
    BOOST_REQUIRE_EQUAL(sockman.m_listen.size(), 1);

    // Pick up the phone, there's no one there
    CService addr_connection;
    BOOST_REQUIRE(!sockman.AcceptConnection(*sockman.m_listen.front(), addr_connection));

    // Create a mock client and add it to the local CreateSock queue
    ConnectClient();
    // Accept the connection
    BOOST_REQUIRE(sockman.AcceptConnection(*sockman.m_listen.front(), addr_connection));
    BOOST_CHECK_EQUAL(addr_connection.ToStringAddrPort(), "5.5.5.5:6789");
}

BOOST_AUTO_TEST_SUITE_END()

#include <boost/test/unit_test.hpp>
#include <common/sv2_connman.h>
#include <common/sv2_messages.h>
#include <common/sv2_transport.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <util/sock.h>

#include <array>
#include <memory>

BOOST_FIXTURE_TEST_SUITE(sv2_connman_tests, TestChain100Setup)

class ListenSock : public ZeroSock
{
public:
    explicit ListenSock(std::vector<std::shared_ptr<DynSock::Pipes>>& pipes) : m_pipes{pipes} {}

    ~ListenSock() override;

    /**
     * Pretend that a new connection has arrived and was accepted.
     */
    std::unique_ptr<Sock> Accept(sockaddr* addr, socklen_t* addr_len) const override
    {
        // Return sockets associated with pipes from m_pipes[] until it is
        // exhausted. After this return nullptr.
        if (m_num_accept_called < m_pipes.size()) {
            // Set addr and addr_len to some meaningful values.
            ZeroSock::Accept(addr, addr_len);

            return std::make_unique<DynSock>(m_pipes.at(m_num_accept_called++));
        }
        return nullptr;
    }

    bool IsConnected(std::string&) const override { return true; }

private:
    ListenSock& operator=(Sock&&) override
    {
        std::abort();
        return *this;
    }

    mutable size_t m_num_accept_called{0};
    std::vector<std::shared_ptr<DynSock::Pipes>>& m_pipes;
};

ListenSock::~ListenSock() {}

/**
  * A class for testing the Sv2Connman. Each ConnTester encapsulates a
  * Sv2Connman (the one being tested) as well as a Sv2Cipher
  * to act as the other side.
  */
class ConnTester : Sv2EventsInterface {
private:
    std::unique_ptr<Sv2Transport> m_peer_transport; //!< Transport for peer
    // Send and receive pipes associated with the Sv2Connman's socket that has
    // accepted a client connection.
    std::vector<std::shared_ptr<DynSock::Pipes>> m_pipes;
    // Which one of m_pipes[] to use.
    ssize_t m_pipes_i{-1};
    XOnlyPubKey m_connman_authority_pubkey;

public:
    std::unique_ptr<Sv2Connman> m_connman; //!< Sv2Connman being tested

    ConnTester()
    {
        CreateSock = [this](int, int, int) -> std::unique_ptr<Sock> {
            // This will be the bind/listen socket from m_connman. It will
            // create other sockets via its Accept() method.
            return std::make_unique<ListenSock>(m_pipes);
        };

        CKey static_key;
        static_key.MakeNewKey(true);
        auto authority_key{GenerateRandomKey()};
        m_connman_authority_pubkey = XOnlyPubKey(authority_key.GetPubKey());

        // Generate and sign certificate
        auto now{GetTime<std::chrono::seconds>()};
        uint16_t version = 0;
        // Start validity a little bit in the past to account for clock difference
        uint32_t valid_from = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(now).count()) - 3600;
        uint32_t valid_to =  std::numeric_limits<unsigned int>::max(); // 2106
        Sv2SignatureNoiseMessage certificate{version, valid_from, valid_to, XOnlyPubKey(static_key.GetPubKey()), authority_key};

        m_connman = std::make_unique<Sv2Connman>(TP_SUBPROTOCOL, static_key, m_connman_authority_pubkey, certificate);
    }

    ~ConnTester()
    {
        CreateSock = CreateSockOS;
    }

    bool start()
    {
        BOOST_REQUIRE(m_connman->Start(this, "127.0.0.1", 18447));
        return true;
    }

    void SendPeerBytes()
    {
        BOOST_REQUIRE(m_pipes_i != -1);
        const auto& [data, more, _m_message_type] = m_peer_transport->GetBytesToSend(/*have_next_message=*/false);
        BOOST_REQUIRE(data.size() > 0);
        // Schedule data to be returned by the next Recv() call from
        // Sv2Connman on the socket it has accepted.
        m_pipes[m_pipes_i]->recv.PushBytes(data.data(), data.size());
        m_peer_transport->MarkBytesSent(data.size());
    }

    // Have the peer receive and process bytes:
    size_t PeerReceiveBytes()
    {
        BOOST_REQUIRE(m_pipes_i != -1);
        uint8_t buf[0x10000];
        // Get the data that has been written to the accepted socket with
        // Send() by Sv2Connman.
        UninterruptibleSleep(1000ms); // XXX, wait until the bytes appear in the "send" pipe
        const auto n = m_pipes[m_pipes_i]->send.GetBytes(buf, sizeof(buf), 0);
        assert(n > 0);

        // Inform client's transport that some bytes have been received (sent by Sv2Connman).
        Span<const uint8_t> s(buf, n);
        BOOST_REQUIRE(m_peer_transport->ReceivedBytes(s));

        return n;
    }

    /* Create a new client and perform handshake */
    void handshake()
    {
        m_peer_transport.reset();

        auto peer_static_key{GenerateRandomKey()};
        m_peer_transport = std::make_unique<Sv2Transport>(std::move(peer_static_key), m_connman_authority_pubkey);

        // Doing this any earlier causes an immedidate disconnect
        m_pipes.push_back(std::make_shared<DynSock::Pipes>());
        ++m_pipes_i;
        assert(static_cast<size_t>(m_pipes_i) < m_pipes.size());

        // Flush transport for handshake part 1
        SendPeerBytes();

        // Read handshake part 2 from transport
        BOOST_REQUIRE_EQUAL(PeerReceiveBytes(), Sv2HandshakeState::HANDSHAKE_STEP2_SIZE);
    }

    void receiveMessage(Sv2NetMsg& msg)
    {
        // Client encrypts message and puts it on the transport:
        CSerializedNetMsg net_msg{std::move(msg)};
        BOOST_REQUIRE(m_peer_transport->SetMessageToSend(net_msg));
        SendPeerBytes();
    }

    bool IsConnected()
    {
        LOCK(m_connman->m_clients_mutex);
        return m_connman->ConnectedClients() > 0;
    }

    bool IsFullyConnected()
    {
        LOCK(m_connman->m_clients_mutex);
        return m_connman->FullyConnectedClients() > 0;
    }

    Sv2NetMsg SetupConnectionMsg()
    {
        std::vector<uint8_t> bytes{
            0x02,                                                 // protocol
            0x02, 0x00,                                           // min_version
            0x02, 0x00,                                           // max_version
            0x01, 0x00, 0x00, 0x00,                               // flags
            0x07, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x30,       // endpoint_host
            0x61, 0x21,                                           // endpoint_port
            0x07, 0x42, 0x69, 0x74, 0x6d, 0x61, 0x69, 0x6e,       // vendor
            0x08, 0x53, 0x39, 0x69, 0x20, 0x31, 0x33, 0x2e, 0x35, // hardware_version
            0x1c, 0x62, 0x72, 0x61, 0x69, 0x69, 0x6e, 0x73, 0x2d, 0x6f, 0x73, 0x2d, 0x32, 0x30,
            0x31, 0x38, 0x2d, 0x30, 0x39, 0x2d, 0x32, 0x32, 0x2d, 0x31, 0x2d, 0x68, 0x61, 0x73,
            0x68, // firmware
            0x10, 0x73, 0x6f, 0x6d, 0x65, 0x2d, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x2d, 0x75,
            0x75, 0x69, 0x64, // device_id
        };

        return node::Sv2NetMsg{node::Sv2MsgType::SETUP_CONNECTION, std::move(bytes)};
    }

    void ReceivedMessage(Sv2Client& client, node::Sv2MsgType msg_type) override {
        BOOST_TEST_MESSAGE("Process message callback");
    }

};

BOOST_AUTO_TEST_CASE(client_tests)
{
    ConnTester tester{};
    BOOST_REQUIRE(tester.start());

    BOOST_REQUIRE(!tester.IsConnected());
    tester.handshake();
    BOOST_REQUIRE(tester.IsConnected());
    BOOST_REQUIRE(!tester.IsFullyConnected());

    // After the handshake the client must send a SetupConnection message to the
    // Template Provider.

    // An empty SetupConnection message should cause disconnection
    node::Sv2NetMsg sv2_msg{node::Sv2MsgType::SETUP_CONNECTION, {}};
    tester.receiveMessage(sv2_msg);
    BOOST_REQUIRE_EQUAL(tester.PeerReceiveBytes(), 0);

    BOOST_REQUIRE(!tester.IsConnected());

    BOOST_TEST_MESSAGE("Reconnect after empty message");

    // Reconnect
    tester.handshake();
    BOOST_REQUIRE(tester.IsConnected());
    BOOST_TEST_MESSAGE("Handshake done, send SetupConnectionMsg");

    node::Sv2NetMsg setup{tester.SetupConnectionMsg()};
    tester.receiveMessage(setup);
    // SetupConnection.Success is 6 bytes
    BOOST_REQUIRE_EQUAL(tester.PeerReceiveBytes(), SV2_HEADER_ENCRYPTED_SIZE + 6 + Poly1305::TAGLEN);
    BOOST_REQUIRE(tester.IsFullyConnected());

    std::vector<uint8_t> coinbase_output_max_additional_size_bytes{
        0x01, 0x00, 0x00, 0x00
    };
    node::Sv2NetMsg msg{node::Sv2MsgType::COINBASE_OUTPUT_DATA_SIZE, std::move(coinbase_output_max_additional_size_bytes)};
    // No reply expected, not yet implemented
    tester.receiveMessage(msg);
}

BOOST_AUTO_TEST_SUITE_END()

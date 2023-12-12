#include <node/sv2_template_provider.h>

#include <util/thread.h>
#include <validation.h>

void Sv2TemplateProvider::Start(const Sv2TemplateProviderOptions& options)
{
    Init(options);

    // Here we are checking if we can bind to the port. If we can't, then exit
    // early and shutdown the node gracefully. This would be called in init.cpp
    // and allows the caller to see that the node is unable to run with the current
    // sv2 config.
    //
    // The socket is dropped within this scope and re-opened on the same port in
    // ThreadSv2Handler() when the node has finished IBD.
    auto sock = BindListenPort(options.port);

    m_thread_sv2_handler = std::thread(&util::TraceThread, "sv2", [this] { ThreadSv2Handler(); });
}

void Sv2TemplateProvider::Init(const Sv2TemplateProviderOptions& options)
{
    m_port = options.port;
    m_protocol_version = options.protocol_version;
    m_optional_features = options.optional_features;
    m_default_coinbase_tx_additional_output_size = options.default_coinbase_tx_additional_output_size;
}

Sv2TemplateProvider::~Sv2TemplateProvider()
{
    for (const auto& client : m_sv2_clients) {
        client->m_disconnect_flag = true;
    }

    DisconnectFlagged();
    Interrupt();
    StopThreads();
}

void Sv2TemplateProvider::Interrupt()
{
    m_flag_interrupt_sv2 = true;
}

void Sv2TemplateProvider::StopThreads()
{
    if (m_thread_sv2_handler.joinable()) {
        m_thread_sv2_handler.join();
    }
}

std::shared_ptr<Sock> Sv2TemplateProvider::BindListenPort(uint16_t port) const
{
    const CService addr_bind = LookupNumeric("0.0.0.0", port);

    auto sock = CreateSock(addr_bind);
    if (!sock) {
        throw std::runtime_error("Sv2 Template Provider cannot create socket");
    }

    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);

    if (!addr_bind.GetSockAddr(reinterpret_cast<struct sockaddr*>(&sockaddr), &len)) {
        throw std::runtime_error("Sv2 Template Provider failed to get socket address");
    }

    if (sock->Bind(reinterpret_cast<struct sockaddr*>(&sockaddr), len) == SOCKET_ERROR) {
        const int nErr = WSAGetLastError();
        if (nErr == WSAEADDRINUSE) {
            throw std::runtime_error(strprintf("Unable to bind to %d on this computer. %s is probably already running.\n", port, PACKAGE_NAME));
        }

        throw std::runtime_error(strprintf("Unable to bind to %d on this computer (bind returned error %s )\n", port, NetworkErrorString(nErr)));
    }

    constexpr int max_pending_conns{4096};
    if (sock->Listen(max_pending_conns) == SOCKET_ERROR) {
        throw std::runtime_error("Sv2 Template Provider listening socket has an error listening");
    }

    return sock;
}

void Sv2TemplateProvider::DisconnectFlagged()
{
    // Remove clients that are flagged for disconnection.
    m_sv2_clients.erase(
        std::remove_if(m_sv2_clients.begin(), m_sv2_clients.end(), [](const auto &client) {
            return client->m_disconnect_flag;
    }), m_sv2_clients.end());
}

void Sv2TemplateProvider::ThreadSv2Handler()
{
    while (!m_flag_interrupt_sv2) {
        if (m_chainman.IsInitialBlockDownload()) {
            m_interrupt_sv2.sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        // If we've left IBD. Create the listening socket for new sv2 connections.
        if (!m_listening_socket) {
            try {
                auto socket = BindListenPort(m_port);
                m_listening_socket = std::move(socket);
            } catch (const std::runtime_error& e) {
                LogPrintLevel(BCLog::SV2, BCLog::Level::Error, "thread shutting down due to exception: %s\n", e.what());
                Interrupt();
                continue;
            }

            LogPrintLevel(BCLog::SV2, BCLog::Level::Info, "Template Provider listening on port: %d\n", m_port);
        }

        DisconnectFlagged();

        // Poll/Select the sockets that need handling.
        Sock::EventsPerSock events_per_sock = GenerateWaitSockets(m_listening_socket, m_sv2_clients);

        constexpr auto timeout = std::chrono::milliseconds(50);
        if (!events_per_sock.begin()->first->WaitMany(timeout, events_per_sock)) {
            continue;
        }

        // Accept any new connections for sv2 clients.
        const auto listening_sock = events_per_sock.find(m_listening_socket);
        if (listening_sock != events_per_sock.end() && listening_sock->second.occurred & Sock::RECV) {
            struct sockaddr_storage sockaddr;
            socklen_t sockaddr_len = sizeof(sockaddr);

            auto sock = m_listening_socket->Accept(reinterpret_cast<struct sockaddr*>(&sockaddr), &sockaddr_len);
            if (sock) {
                m_sv2_clients.emplace_back(std::make_unique<Sv2Client>(Sv2Client{std::move(sock)}));
            }
        }

        // Process messages from connected sv2_clients.
        for (auto& client : m_sv2_clients) {
            bool has_received_data = false;
            bool has_error_occurred = false;

            const auto it = events_per_sock.find(client->m_sock);
            if (it != events_per_sock.end()) {
                has_received_data = it->second.occurred & Sock::RECV;
                has_error_occurred = it->second.occurred & Sock::ERR;
            }

            if (has_error_occurred) {
                client->m_disconnect_flag = true;
            }

            if (has_received_data) {
                uint8_t bytes_received_buf[0x10000];

                const auto num_bytes_received = client->m_sock->Recv(bytes_received_buf, sizeof(bytes_received_buf), MSG_DONTWAIT);
                LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "Num bytes received: %d\n", num_bytes_received);

                if (num_bytes_received <= 0) {
                    client->m_disconnect_flag = true;
                    continue;
                }

                try
                {
                    if (!client->m_noise->HandshakeComplete()) {
                        auto headers_recv = ReadSv2NoiseHeaders(Span(bytes_received_buf), num_bytes_received);
                        for (auto& header : headers_recv)
                        {
                            ProcessSv2Noise(*client.get(), header.m_payload);
                        }
                    } else {
                        auto sv2_msgs = ReadAndDecryptSv2NetMsgs(*client.get(), Span(bytes_received_buf), num_bytes_received);

                        for (auto& m : sv2_msgs)
                        {
                            ProcessSv2Message(m, *client.get());
                        }
                    }
                } catch (const std::exception& e) {
                    LogPrintLevel(BCLog::SV2, BCLog::Level::Error, "Received error when processing client message: %s\n", e.what());
                    client->m_disconnect_flag = true;
                }
            }
        }
    }
}

void Sv2TemplateProvider::ProcessSv2Noise(Sv2Client& client, Span<std::byte> buffer)
{
    switch(client.m_noise->GetSessionState())
    {
        case SessionState::HANDSHAKE_STEP_1:
        {
            // Expect to read the E msg.
            client.m_noise->ReadMsg(buffer);

            // Send the Msg ES.
            Sv2NoiseHeader msg_es;
            auto num_bytes = client.m_noise->SendMsg(msg_es.m_payload);
            msg_es.m_header = num_bytes;
            msg_es.m_payload.resize(num_bytes);

            if (!Send(client, msg_es)) {
                throw std::runtime_error("Sv2TemplateProvider::ProcessSv2Message(): Failed to send Msg ES to client\n");
            }
            break;
        }
        case SessionState::HANDSHAKE_STEP_2:
        {
            break;
        }
        case SessionState::CIPHER_CONFIRMATION:
        {
            client.m_noise->ReadMsg(buffer);

            CipherChoice cipher_choice;
            auto cipher_choice_header = Sv2NoiseHeader(cipher_choice, false);
            if (!Send(client, cipher_choice_header)) {
                throw std::runtime_error("Sv2TemplateProvider::ProcessSv2Message(): Failed to send CipherConfirmation to client\n");
            }

            break;
        }
        case SessionState::TRANSPORT:
        {
            client.m_noise->ReadMsg(buffer);
            break;
        }
    }
}

Sock::EventsPerSock Sv2TemplateProvider::GenerateWaitSockets(const std::shared_ptr<Sock>& listen_socket, const Clients& sv2_clients) const
{
    Sock::EventsPerSock events_per_sock;
    events_per_sock.emplace(listen_socket, Sock::Events(Sock::RECV));

    for (const auto& client : sv2_clients) {
        if (!client->m_disconnect_flag && client->m_sock) {
            events_per_sock.emplace(client->m_sock, Sock::Events{Sock::RECV | Sock::ERR});
        }
    }

    return events_per_sock;
}

void Sv2TemplateProvider::ProcessSv2Message(const node::Sv2NetMsg& sv2_net_msg, Sv2Client& client)
{
    DataStream ss (sv2_net_msg.m_msg);

    switch (sv2_net_msg.m_sv2_header.m_msg_type)
    {
    case node::Sv2MsgType::SETUP_CONNECTION:
    {
        LogPrintLevel(BCLog::SV2, BCLog::Level::Debug, "Received 0x00 SetupConnection\n");

        if (client.m_setup_connection_confirmed) {
            LogPrintLevel(BCLog::SV2, BCLog::Level::Error, "Client connection has already been confirmed\n");
            return;
        }

        node::Sv2SetupConnectionMsg setup_conn;
        try {
            ss >> setup_conn;
        } catch (const std::exception& e) {
            LogPrintLevel(BCLog::SV2, BCLog::Level::Error, "Received invalid SetupConnection message: %s\n", e.what());
            client.m_disconnect_flag = true;
            return;
        }

        // Disconnect a client that connects on the wrong subprotocol.
        if (setup_conn.m_protocol != TP_SUBPROTOCOL) {
          node::Sv2SetupConnectionErrorMsg setup_conn_err{setup_conn.m_flags, std::string{"unsupported-protocol"}};
          auto msg = node::Sv2NetMsg{setup_conn_err};
          auto msg_buf = BuildEncryptedHeader(msg, *client.m_noise.get());

          LogPrintLevel(BCLog::SV2, BCLog::Level::Debug, "Send 0x02 SetupConnectionError\n");

          try {
            if (!SendBuf(client, msg_buf)) {
              LogPrintLevel(BCLog::SV2, BCLog::Level::Error, "Failed to send Sv2SetupConnectionError message\n");
            }
          } catch (const std::exception& e) {
             LogPrintLevel(BCLog::SV2, BCLog::Level::Error, "Failed to serialize best new prev hash: %s\n", e.what());
          }

            client.m_disconnect_flag = true;
            return;
        }

        // Disconnect a client if they are not running a compatible protocol version.
        if ((m_protocol_version < setup_conn.m_min_version) || (m_protocol_version > setup_conn.m_max_version)) {
            node::Sv2SetupConnectionErrorMsg setup_conn_err{setup_conn.m_flags, std::string{"protocol-version-mismatch"}};
            auto msg = node::Sv2NetMsg{setup_conn_err};
            auto msg_buf = BuildEncryptedHeader(msg, *client.m_noise.get());

            LogPrintLevel(BCLog::SV2, BCLog::Level::Debug, "Send 0x02 SetupConnection.Error\n");

            try {
                if (!SendBuf(client, msg_buf)) {
                    LogPrintLevel(BCLog::SV2, BCLog::Level::Error, "Failed to send SetupConnection.Error message\n");
                }
            } catch (const std::exception& e) {
                LogPrintLevel(BCLog::SV2, BCLog::Level::Error, "Failed to serialize best new prev hash: %s\n", e.what());
            }

            LogPrintLevel(BCLog::SV2, BCLog::Level::Error, "Received a connection with incompatible protocol_versions: min_version: %d, max_version: %d\n", setup_conn.m_min_version, setup_conn.m_max_version);
            client.m_disconnect_flag = true;
            return;
        }

        node::Sv2SetupConnectionSuccessMsg setup_success{m_protocol_version, m_optional_features};
        auto msg = node::Sv2NetMsg{setup_success};
        auto msg_buf = BuildEncryptedHeader(msg, *client.m_noise.get());

        try{
            LogPrintLevel(BCLog::SV2, BCLog::Level::Debug, "Send 0x01 SetupConnection.Success\n");
            if (!SendBuf(client, msg_buf)) {
                LogPrintLevel(BCLog::SV2, BCLog::Level::Error, "Failed to send SetupConnection.Success message\n");
                client.m_disconnect_flag = true;
                return;
            }
        }catch (const std::exception& e) {
            LogPrintLevel(BCLog::SV2, BCLog::Level::Error, "Failed to serialize setup success message: %s\n", e.what());
            client.m_disconnect_flag = true;
            return;
        }

        client.m_setup_connection_confirmed = true;

        break;
    }
    case node::Sv2MsgType::COINBASE_OUTPUT_DATA_SIZE:
    {
        LogPrintLevel(BCLog::SV2, BCLog::Level::Debug, "Received 0x70 CoinbaseOutputDataSize\n");

        if (!client.m_setup_connection_confirmed) {
            client.m_disconnect_flag = true;
            return;
        }

        node::Sv2CoinbaseOutputDataSizeMsg coinbase_output_data_size;
        try {
            ss >> coinbase_output_data_size;
            client.m_coinbase_output_data_size_recv = true;
        } catch (const std::exception& e) {
            LogPrintLevel(BCLog::SV2, BCLog::Level::Error, "Received invalid CoinbaseOutputDataSize message: %s\n", e.what());
            client.m_disconnect_flag = true;
            return;
        }

        LogPrintLevel(BCLog::SV2, BCLog::Level::Debug, "coinbase_output_max_additional_size=%d bytes\n", coinbase_output_data_size.m_coinbase_output_max_additional_size);

        client.m_coinbase_tx_outputs_size = coinbase_output_data_size.m_coinbase_output_max_additional_size;

        break;
    }
    default: {
        uint8_t msg_type[1]{uint8_t(sv2_net_msg.m_sv2_header.m_msg_type)};
        LogPrintLevel(BCLog::SV2, BCLog::Level::Warning, "Received unknown message type 0x%s\n", HexStr(msg_type));
        break;
    }
    }
}

std::vector<std::byte> Sv2TemplateProvider::BuildEncryptedHeader(const node::Sv2NetMsg& net_msg, Sv2NoiseSession& noise)
{
    DataStream ss_header{};
    ss_header << net_msg.m_sv2_header;

    auto constexpr header_and_mac_size = 22;
    ss_header.resize(header_and_mac_size);
    noise.SendMsg(ss_header);

    LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "To encrypt: %s\n", HexStr(net_msg.m_msg));

    DataStream ss_payload {};
    ss_payload.write(MakeByteSpan(net_msg.m_msg));
    ss_payload.resize(net_msg.m_msg.size() + POLY1305_TAGLEN);
    noise.SendMsg(ss_payload);

    std::vector<std::byte> msg_buf;
    msg_buf.reserve(ss_header.size() + ss_payload.size());
    msg_buf.insert(msg_buf.end(), ss_header.begin(), ss_header.end());
    msg_buf.insert(msg_buf.end(), ss_payload.begin(), ss_payload.end());

    return msg_buf;
};

std::vector<Sv2NoiseHeader> Sv2TemplateProvider::ReadSv2NoiseHeaders(Span<uint8_t> buffer, ssize_t num_bytes)
{
    auto bytes_read = 0;
    DataStream ss (buffer);
    std::vector<Sv2NoiseHeader> headers;
    while (bytes_read < num_bytes)
    {
        Sv2NoiseHeader header;
        ss >> header;

        bytes_read += header.m_header + 2;
        headers.push_back(std::move(header));
    }

    return headers;
}

std::vector<node::Sv2NetMsg> Sv2TemplateProvider::ReadAndDecryptSv2NetMsgs(Sv2Client& client, Span<uint8_t> buffer, ssize_t num_bytes)
{
    auto bytes_read = 0;
    std::vector<node::Sv2NetMsg> sv2_msgs;

    auto constexpr header_and_mac_size = 22;

    while (bytes_read < num_bytes)
    {
        // Decrypt the header.
        DataStream ss_header (Span(&buffer[bytes_read], header_and_mac_size));
        ProcessSv2Noise(client, ss_header);

        node::Sv2NetHeader header;
        ss_header >> header;

        bytes_read += header_and_mac_size;

        // Decrypt the payload.
        DataStream ss_payload (Span(&buffer[bytes_read], header.m_msg_len + POLY1305_TAGLEN));

        ProcessSv2Noise(client, ss_payload);

        bytes_read += header.m_msg_len + POLY1305_TAGLEN;

        std::vector<uint8_t> msg_payload(ss_payload.size());
        std::transform(ss_payload.begin(), ss_payload.end(), msg_payload.begin(),
                           [](std::byte b) { return static_cast<uint8_t>(b); });

        sv2_msgs.emplace_back(node::Sv2NetMsg{std::move(header), std::move(msg_payload)});
    }

    return sv2_msgs;
}

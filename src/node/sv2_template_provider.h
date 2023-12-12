#ifndef BITCOIN_NODE_SV2_TEMPLATE_PROVIDER_H
#define BITCOIN_NODE_SV2_TEMPLATE_PROVIDER_H

#include <common/sv2_messages.h>
#include <common/sv2_noise.h>
#include <logging.h>
#include <net.h>
#include <node/miner.h>
#include <util/sock.h>
#include <streams.h>

class ChainstateManager;
class CTxMemPool;

struct Sv2Client
{
    /**
     * Receiving and sending socket for the connected client
     */
    std::shared_ptr<Sock> m_sock;

    /**
     * Whether the client has confirmed the connection with a successful SetupConnection.
     */
    bool m_setup_connection_confirmed;

    /**
     * Whether the client is a candidate for disconnection.
     */
    bool m_disconnect_flag;

    /**
     * Whether the client has received CoinbaseOutputDataSize message.
     */
    bool m_coinbase_output_data_size_recv;

    /**
     * Specific additional coinbase tx output size required for the client.
     */
    unsigned int m_coinbase_tx_outputs_size;

    /**
     * The noise sessions for secure communication for this client and the template
     * provider server.
     */
    std::unique_ptr<Sv2NoiseSession> m_noise;

    explicit Sv2Client(std::shared_ptr<Sock> sock) : m_sock{sock}
    {
        CKey static_key;
        static_key.MakeNewKey(true);
        while (!static_key.HasEvenY()) {
            static_key.MakeNewKey(true);
        }

        m_noise = std::make_unique<Sv2NoiseSession>(Sv2NoiseSession(false /* initiator */, std::move(static_key)));
    };
};

struct Sv2TemplateProviderOptions
{
    /**
     * The listening port for the server.
     */
    uint16_t port;

    /**
     * The current protocol version of stratum v2 supported by the server. Not to be confused
     * with byte value of identitying the stratum v2 subprotocol.
     */
    uint16_t protocol_version = 2;

    /**
     * Optional protocol features provided by the server.
     */
    uint16_t optional_features = 0;

    /**
     * The default option for the additional space required for coinbase output.
     */
    unsigned int default_coinbase_tx_additional_output_size = 0;

    /**
     * The default flag for all new work.
     */
    bool default_future_templates = true;
};

/**
 * The main class that runs the template provider server.
 */
class Sv2TemplateProvider
{

private:
    /**
     * The template provider subprotocol used in setup connection messages. The stratum v2
     * template provider only recognizes its own subprotocol.
     */
    static constexpr uint8_t TP_SUBPROTOCOL{0x02};

    /**
     * The main listening socket for new stratum v2 connections.
     */
    std::shared_ptr<Sock> m_listening_socket;

    /**
     * The main thread for the template provider.
     */
    std::thread m_thread_sv2_handler;

    /**
     * Signal for handling interrupts and stopping the template provider event loop.
     */
    std::atomic<bool> m_flag_interrupt_sv2{false};
    CThreadInterrupt m_interrupt_sv2;

    /**
    * ChainstateManager and CTxMemPool are both used to build new valid blocks,
    * getting the best known block hash and checking whether the node is still
    * in IBD.
    */
    ChainstateManager& m_chainman;
    CTxMemPool& m_mempool;

    /**
     * A list of all connected stratum v2 clients.
     */
    using Clients = std::vector<std::unique_ptr<Sv2Client>>;
    Clients m_sv2_clients;

    /**
     * The most recent template id. This is incremented on creating new template,
     * which happens for each connected client.
     */
    uint64_t m_template_id;

    /**
     * The current best known SetNewPrevHash that references the current best known
     * block hash in the network.
     */
    node::Sv2SetNewPrevHashMsg m_best_prev_hash;

    /**
     * A cache that maps ids used in NewTemplate messages and its associated block.
     */
    using BlockCache = std::map<uint64_t, std::unique_ptr<node::CBlockTemplate>>;
    BlockCache m_block_cache;

    /**
     * The currently supported protocol version.
     */
    uint16_t m_protocol_version;

    /**
     * The currently supported optional features.
     */
    uint16_t m_optional_features;

    /**
     * The default additional size output required for NewTemplates.
     */
    unsigned int m_default_coinbase_tx_additional_output_size;

    /**
     * The default setting for sending future templates.
     */
    bool m_default_future_templates;

    /**
     * The configured port to listen for new connections.
     */
    uint16_t m_port;

public:
    explicit Sv2TemplateProvider(ChainstateManager& chainman, CTxMemPool& mempool) : m_chainman{chainman}, m_mempool{mempool}
    {
        Init({});
    }

    ~Sv2TemplateProvider();
    /**
     * Starts the template provider server and thread.
     * @throws std::runtime_error if port is unable to bind.
     */
    void Start(const Sv2TemplateProviderOptions& options);

    /**
     * Triggered on interrupt signals to stop the main event loop in ThreadSv2Handler().
     */
    void Interrupt();

    /**
     * Tear down of the template provider thread and any other necessary tear down.
     */
    void StopThreads();

    /**
     * Main handler for all received stratum v2 messages.
     */
    void ProcessSv2Message(const node::Sv2NetMsg& sv2_header, Sv2Client& client);

    /**
     * A helper function to process incoming noise messages to either progress a handshake or encrypt/decrypt in secure communication.
     * @throws std::runtime_error if any point of the handshake, encryption/decryption fails.
     */
    void ProcessSv2Noise(Sv2Client& client, Span<std::byte> buffer);

private:
    void Init(const Sv2TemplateProviderOptions& options);

    /**
     * Creates a socket and binds the port for new stratum v2 connections.
     * @throws std::runtime_error if port is unable to bind.
     */
    [[nodiscard]] std::shared_ptr<Sock> BindListenPort(uint16_t port) const;

    void DisconnectFlagged();

    /**
     * The main thread for the template provider, contains an event loop handling
     * all tasks for the template provider.
     */
    void ThreadSv2Handler();

    /**
     * NewWorkSet contains the messages matching block for valid stratum v2 work.
     */
    struct NewWorkSet
    {
        node::Sv2NewTemplateMsg new_template;
        std::unique_ptr<node::CBlockTemplate> block_template;
        node::Sv2SetNewPrevHashMsg prev_hash;
    };

    /**
     * Builds a NewWorkSet that contains the Sv2NewTemplateMsg, a new full block and a Sv2SetNewPrevHashMsg that are all linked to the same work.
     */
    [[nodiscard]] NewWorkSet BuildNewWorkSet(bool future_template, unsigned int coinbase_output_max_additional_size);

    /**
     * Sends the best NewTemplate and SetNewPrevHash to a client.
     */
    [[nodiscard]] bool SendWork(const Sv2Client& client, bool send_new_prevhash);

    /**
     * Generates the socket events for each Sv2Client socket and the main listening socket.
     */
    [[nodiscard]] Sock::EventsPerSock GenerateWaitSockets(const std::shared_ptr<Sock>& listen_socket, const Clients& sv2_clients) const;

    /**
     * A helper method to encrypt the header and message payload.
     * @throws std::runtime_error if encrypting the message fails.
     */
    std::vector<std::byte> BuildEncryptedHeader(const node::Sv2NetMsg& net_msg, Sv2NoiseSession& noise);

    /**
     * A helper method to read multiple stratumv2 headers from a buffer.
     * @throws std::runtime_error if deserializing the noise header fails.
     */
    std::vector<Sv2NoiseHeader> ReadSv2NoiseHeaders(Span<uint8_t> buffer, ssize_t num_bytes);

    /**
     * A helper method to read and decrypt multiple Sv2NetMsgs.
     */
    std::vector<node::Sv2NetMsg> ReadAndDecryptSv2NetMsgs(Sv2Client& client, Span<uint8_t> buffer, ssize_t num_bytes);

    /**
     * A helper method that will serialize and send a message to an Sv2Client.
     */
    template <typename T>
    [[nodiscard]] bool Send(const Sv2Client& client, const T& sv2_msg) {
        DataStream ss{};

        try {
            ss << sv2_msg;
        } catch (const std::exception& e) {
            LogPrintf("Error serializing Sv2NetMsg: %s\n", e.what());
            return false;
        }

        return SendBuf(client, ss);
    }

    /**
     * A helper method that will send a buffer of bytes to an Sv2Client.
     */
    [[nodiscard]] bool SendBuf(const Sv2Client& client, Span<std::byte> buffer) {
        size_t total_sent = 0;
        try {
            LogPrintf("Try to send: %d\n", buffer.size());
            while (total_sent < buffer.size()) {
                ssize_t sent = client.m_sock->Send(buffer.data() + total_sent, buffer.size() - total_sent, MSG_NOSIGNAL | MSG_DONTWAIT);
                if (sent > 0) {
                    total_sent += sent;
                } else if (sent == 0) {
                    usleep(10);
                } else {
                    usleep(100);
                }
            }
            LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "Sent buf byte size: %d\n", total_sent);
        } catch (const std::exception& e) {
            LogPrintLevel(BCLog::SV2, BCLog::Level::Error, "Error sending Sv2NetMsg: %s\n", e.what());
            return false;
        }

        if (total_sent != buffer.size()) {
            return false;
        }

        return true;
    }

};

#endif // BITCOIN_NODE_SV2_TEMPLATE_PROVIDER_H

#ifndef BITCOIN_SV2_TEMPLATE_PROVIDER_H
#define BITCOIN_SV2_TEMPLATE_PROVIDER_H

#include <chrono>
#include <interfaces/mining.h>
#include <sv2/connman.h>
#include <sv2/messages.h>
#include <logging.h>
#include <net.h>
#include <util/sock.h>
#include <util/time.h>
#include <streams.h>

using interfaces::BlockTemplate;

struct Sv2TemplateProviderOptions
{
    /**
     * Running inside a test
     */
    bool is_test{false};

    /**
     * Host for the server to bind to.
     */
    std::string host{"127.0.0.1"};

    /**
     * The listening port for the server.
     */
    uint16_t port{8336};

    /**
     * Minimum fee delta to send new template upstream
     */
    CAmount fee_delta{1000};

    /**
     * Block template update interval (to check for increased fees)
     */
    std::chrono::seconds fee_check_interval{30};
};

/**
 * The main class that runs the template provider server.
 */
class Sv2TemplateProvider : public Sv2EventsInterface
{

private:
    /**
    * The Mining interface is used to build new valid blocks, get the best known
    * block hash and to check whether the node is still in IBD.
    */
    interfaces::Mining& m_mining;

    /*
     * The template provider subprotocol used in setup connection messages. The stratum v2
     * template provider only recognizes its own subprotocol.
     */
    static constexpr uint8_t TP_SUBPROTOCOL{0x02};

    std::unique_ptr<Sv2Connman> m_connman;

    /** Get name of file to store static key */
    fs::path GetStaticKeyFile();

    /** Get name of file to store authority key */
    fs::path GetAuthorityKeyFile();

    /**
    * Configuration
    */
    Sv2TemplateProviderOptions m_options;

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
     * The most recent template id. This is incremented on creating new template,
     * which happens for each connected client.
     */
    uint64_t m_template_id GUARDED_BY(m_tp_mutex){0};

    /**
     * The current best known block hash in the network.
     */
    uint256 m_best_prev_hash GUARDED_BY(m_tp_mutex){uint256(0)};

    /** When we last saw a new block connection. Used to cache stale templates
      * for some time after this.
      */
    std::chrono::nanoseconds m_last_block_time GUARDED_BY(m_tp_mutex);

    /**
     * A cache that maps ids used in NewTemplate messages and its associated block template.
     */
    using BlockTemplateCache = std::map<uint64_t, std::shared_ptr<BlockTemplate>>;
    BlockTemplateCache m_block_template_cache GUARDED_BY(m_tp_mutex);

public:
    explicit Sv2TemplateProvider(interfaces::Mining& mining);

    ~Sv2TemplateProvider() EXCLUSIVE_LOCKS_REQUIRED(!m_tp_mutex);

    Mutex m_tp_mutex;

    /**
     * Starts the template provider server and thread.
     * returns false if port is unable to bind.
     */
    [[nodiscard]] bool Start(const Sv2TemplateProviderOptions& options = {});

    /**
     * The main thread for the template provider, contains an event loop handling
     * all tasks for the template provider.
     */
    void ThreadSv2Handler() EXCLUSIVE_LOCKS_REQUIRED(!m_tp_mutex);

    /**
     * Give each client its own thread so they're treated equally
     * and so that newly connected clients don't have to wait.
     * This scales very poorly, because block template creation is
     * slow, but is easier to reason about.
     *
     * A typical miner as well as a typical pool will only need one
     * connection. For the use case of a public facing template provider,
     * further changes are needed anyway e.g. for DoS resistance.
     */
    void ThreadSv2ClientHandler(size_t client_id) EXCLUSIVE_LOCKS_REQUIRED(!m_tp_mutex);

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
    void ProcessSv2Message(const node::Sv2NetMsg& sv2_header, Sv2Client& client) EXCLUSIVE_LOCKS_REQUIRED(!m_tp_mutex);

    // Only used for tests
    XOnlyPubKey m_authority_pubkey;

    void RequestTransactionData(Sv2Client& client, node::Sv2RequestTransactionDataMsg msg) EXCLUSIVE_LOCKS_REQUIRED(!m_tp_mutex) override;

    void SubmitSolution(node::Sv2SubmitSolutionMsg solution) EXCLUSIVE_LOCKS_REQUIRED(!m_tp_mutex) override;

    /* Block templates that connected clients may be working on, only used for tests */
    BlockTemplateCache& GetBlockTemplates() EXCLUSIVE_LOCKS_REQUIRED(m_tp_mutex) { return m_block_template_cache; }

private:

    /* Forget templates from before the last block, but with a few seconds margin. */
    void PruneBlockTemplateCache() EXCLUSIVE_LOCKS_REQUIRED(m_tp_mutex);

    /**
     * Sends the best NewTemplate and SetNewPrevHash to a client.
     *
     * The current implementation doesn't create templates for future empty
     * or speculative blocks. Despite that, we first send NewTemplate with
     * future_template set to true, followed by SetNewPrevHash. We do this
     * both when first connecting and when a new block is found.
     *
     * When the template is update to take newer mempool transactions into
     * account, we set future_template to false and don't send SetNewPrevHash.
     */
    [[nodiscard]] bool SendWork(Sv2Client& client, uint64_t template_id, BlockTemplate& block_template, bool future_template);

};

#endif // BITCOIN_SV2_TEMPLATE_PROVIDER_H

#include <sv2/template_provider.h>

#include <base58.h>
#include <crypto/hex_base.h>
#include <common/args.h>
#include <logging.h>
#include <sv2/noise.h>
#include <util/strencodings.h>
#include <util/thread.h>

Sv2TemplateProvider::Sv2TemplateProvider(interfaces::Mining& mining) : m_mining{mining}
{
    // TODO: persist static key
    CKey static_key;
    static_key.MakeNewKey(true);

    auto authority_key{GenerateRandomKey()};

    // SRI uses base58 encoded x-only pubkeys in its configuration files
    std::array<unsigned char, 34> version_pubkey_bytes;
    version_pubkey_bytes[0] = 1;
    version_pubkey_bytes[1] = 0;
    m_authority_pubkey = XOnlyPubKey(authority_key.GetPubKey());
    std::copy(m_authority_pubkey.begin(), m_authority_pubkey.end(), version_pubkey_bytes.begin() + 2);
    LogInfo("Template Provider authority key: %s\n", EncodeBase58Check(version_pubkey_bytes));
    LogTrace(BCLog::SV2, "Authority key: %s\n", HexStr(m_authority_pubkey));

    // Generate and sign certificate
    auto now{GetTime<std::chrono::seconds>()};
    uint16_t version = 0;
    // Start validity a little bit in the past to account for clock difference
    uint32_t valid_from = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(now).count()) - 3600;
    uint32_t valid_to =  std::numeric_limits<unsigned int>::max(); // 2106
    Sv2SignatureNoiseMessage certificate = Sv2SignatureNoiseMessage(version, valid_from, valid_to, XOnlyPubKey(static_key.GetPubKey()), authority_key);

    // TODO: persist certificate

    m_connman = std::make_unique<Sv2Connman>(TP_SUBPROTOCOL, static_key, m_authority_pubkey, certificate);
}

bool Sv2TemplateProvider::Start(const Sv2TemplateProviderOptions& options)
{
    m_options = options;

    if (!m_connman->Start(this, m_options.host, m_options.port)) {
        return false;
    }

    m_thread_sv2_handler = std::thread(&util::TraceThread, "sv2", [this] { ThreadSv2Handler(); });
    return true;
}

Sv2TemplateProvider::~Sv2TemplateProvider()
{
    AssertLockNotHeld(m_tp_mutex);

    m_connman->Interrupt();
    m_connman->StopThreads();

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

class Timer {
private:
    std::chrono::seconds m_interval;
    std::chrono::seconds m_last_triggered;

public:
    Timer(std::chrono::seconds interval) : m_interval(interval) {
        reset();
    }

    bool trigger() {
        auto now{GetTime<std::chrono::seconds>()};
        if (now - m_last_triggered >= m_interval) {
            m_last_triggered = now;
            return true;
        }
        return false;
    }

    void reset() {
        auto now{GetTime<std::chrono::seconds>()};
        m_last_triggered = now;
    }
};

void Sv2TemplateProvider::ThreadSv2Handler()
{
    // Make sure it's initialized, doesn't need to be accurate.
    {
        LOCK(m_tp_mutex);
        m_last_block_time = GetTime<std::chrono::seconds>();
    }

    // Wait to come out of IBD, except on signet, where we might be the only miner.
    while (!m_flag_interrupt_sv2 && gArgs.GetChainType() != ChainType::SIGNET) {
        // TODO: Wait until there's no headers-only branch with more work than our chaintip.
        //       The current check can still cause us to broadcast a few dozen useless templates
        //       at startup.
        if (!m_mining.isInitialBlockDownload()) break;
        LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "Waiting to come out of IBD\n");
        std::this_thread::sleep_for(1000ms);
    }

    std::map<size_t, std::thread> client_threads;

    while (!m_flag_interrupt_sv2) {
        // We start with one template per client, which has an interface through
        // which we monitor for better templates.

        m_connman->ForEachClient([this, &client_threads](Sv2Client& client) {
            /**
             * The initial handshake is handled on the Sv2Connman thread. This
             * consists of the noise protocol handshake and the initial Stratum
             * v2 messages SetupConnection and CoinbaseOutputConstraints.
             *
             * A further refactor should make that part non-blocking. But for
             * now we spin up a thread here.
             */
            if (!client.m_coinbase_output_constraints_recv) return;

            if (client_threads.contains(client.m_id)) return;

            client_threads.emplace(client.m_id,
                                   std::thread(&util::TraceThread,
                                               strprintf("sv2-%zu", client.m_id),
                                               [this, &client] { ThreadSv2ClientHandler(client.m_id); }));
        });

        // Take a break (handling new connections is not urgent)
        std::this_thread::sleep_for(100ms);

        LOCK(m_tp_mutex);
        PruneBlockTemplateCache();
    }

    for (auto& thread : client_threads) {
        if (thread.second.joinable()) {
            // If the node is shutting down, then all pending waitNext() calls
            // should return in under a second.
            thread.second.join();
        }
    }


}

void Sv2TemplateProvider::ThreadSv2ClientHandler(size_t client_id)
{
    Timer timer(m_options.fee_check_interval);
    std::shared_ptr<BlockTemplate> block_template;

    while (!m_flag_interrupt_sv2) {
        if (!block_template) {
            LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "Generate initial block template for client id=%zu\n",
                          client_id);

            // Create block template and store interface reference
            // TODO: reuse template_id for clients with the same coinbase constraints
            uint64_t template_id{WITH_LOCK(m_tp_mutex, return ++m_template_id;)};

            node::BlockCreateOptions options {.use_mempool = true};
            {
                LOCK(m_connman->m_clients_mutex);
                std::shared_ptr client = m_connman->GetClientById(client_id);
                if (!client) break;

                // The node enforces a minimum of 2000, though not for IPC so we could go a bit
                // lower, but let's not...
                options.block_reserved_weight = 2000 + client->m_coinbase_tx_outputs_size * 4;
            }

            const auto time_start{SteadyClock::now()};
            block_template = m_mining.createNewBlock(options);
            if (!block_template) {
                LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "No new template for client id=%zu, node is shutting down\n",
                    client_id);
                break;
            }

            LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "Assemble template: %.2fms\n",
                Ticks<MillisecondsDouble>(SteadyClock::now() - time_start));

            uint256 prev_hash{block_template->getBlockHeader().hashPrevBlock};
            {
                LOCK(m_tp_mutex);
                if (prev_hash != m_best_prev_hash) {
                    m_best_prev_hash = prev_hash;
                    // Does not need to be accurate
                    m_last_block_time = GetTime<std::chrono::seconds>();
                }

                // Add template to cache before sending it, to prevent race
                // condition: https://github.com/stratum-mining/stratum/issues/1773
                m_block_template_cache.insert({template_id,block_template});
            }

            {
                LOCK(m_connman->m_clients_mutex);
                std::shared_ptr client = m_connman->GetClientById(client_id);
                if (!client) break;

                if (!SendWork(*client, template_id, *block_template, /*future_template=*/true)) {
                    LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "Disconnecting client id=%zu\n",
                                  client_id);
                    client->m_disconnect_flag = true;
                }
            }

            timer.reset();
        }

        // The future template flag is set when there's a new prevhash,
        // not when there's only a fee increase.
        bool future_template{false};

        // -sv2interval=N requires that we don't send fee updates until at least
        // N seconds have gone by. So we first call waitNext() without a fee
        // threshold, and then on the next while iteration we set it.
        // TODO: add test coverage
        const bool check_fees{m_options.is_test || timer.trigger()};

        CAmount fee_delta{check_fees ? m_options.fee_delta : MAX_MONEY};

        node::BlockWaitOptions options;
        options.fee_threshold = fee_delta;
        if (!check_fees) {
            options.timeout = m_options.fee_check_interval;
            LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "Ignore fee changes for -sv2interval seconds, wait for a new tip, client id=%zu\n",
                          client_id);
        } else {
            if (m_options.is_test) {
                options.timeout = MillisecondsDouble(1000);
            }
            LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "Wait for fees to rise by %d sat or a new tip, client id=%zu\n",
                          fee_delta, client_id);
        }

        uint256 old_prev_hash{block_template->getBlockHeader().hashPrevBlock};
        std::shared_ptr<BlockTemplate> tmpl = block_template->waitNext(options);
        // The client may have disconnected during the wait, check now to avoid
        // a spurious IPC call and confusing log statements.
        {
            LOCK(m_connman->m_clients_mutex);
            if (!m_connman->GetClientById(client_id)) break;
        }

        if (tmpl) {
            block_template = tmpl;
            uint256 new_prev_hash{block_template->getBlockHeader().hashPrevBlock};

            {
                LOCK(m_tp_mutex);
                if (new_prev_hash != old_prev_hash) {
                    LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "Tip changed, client id=%zu\n",
                        client_id);
                    future_template = true;
                    m_best_prev_hash = new_prev_hash;
                    // Does not need to be accurate
                    m_last_block_time = GetTime<std::chrono::seconds>();
                }

                ++m_template_id;

                // Add template to cache before sending it, to prevent race
                // condition: https://github.com/stratum-mining/stratum/issues/1773
                m_block_template_cache.insert({m_template_id,block_template});
            }

            {
                LOCK(m_connman->m_clients_mutex);
                std::shared_ptr client = m_connman->GetClientById(client_id);
                if (!client) break;

                if (!SendWork(*client, WITH_LOCK(m_tp_mutex, return m_template_id;), *block_template, future_template)) {
                    LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "Disconnecting client id=%zu\n",
                                client_id);
                    client->m_disconnect_flag = true;
                }
            }

            timer.reset();
        } else {
            // In production this only happens during shutdown, in tests timeouts are expected.
            LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "Timeout for client id=%zu\n",
                          client_id);
        }

        if (m_options.is_test) {
            // Take a break
            std::this_thread::sleep_for(50ms);
        }
    }
}

void Sv2TemplateProvider::RequestTransactionData(Sv2Client& client, node::Sv2RequestTransactionDataMsg msg)
{
    CBlock block;
    {
        LOCK(m_tp_mutex);
        auto cached_block = m_block_template_cache.find(msg.m_template_id);
        if (cached_block == m_block_template_cache.end()) {
            node::Sv2RequestTransactionDataErrorMsg request_tx_data_error{msg.m_template_id, "template-id-not-found"};

            LogDebug(BCLog::SV2, "Send 0x75 RequestTransactionData.Error (template-id-not-found: %zu) to client id=%zu\n",
                    msg.m_template_id, client.m_id);
            LOCK(client.cs_send);
            client.m_send_messages.emplace_back(request_tx_data_error);

            return;
        }
        block = (*cached_block->second).getBlock();
    }

    {
        LOCK(m_tp_mutex);
        if (block.hashPrevBlock != m_best_prev_hash) {
            LogTrace(BCLog::SV2, "Template id=%lu prevhash=%s, tip=%s\n", msg.m_template_id, HexStr(block.hashPrevBlock), HexStr(m_best_prev_hash));
            node::Sv2RequestTransactionDataErrorMsg request_tx_data_error{msg.m_template_id, "stale-template-id"};


            LogDebug(BCLog::SV2, "Send 0x75 RequestTransactionData.Error (stale-template-id) to client id=%zu\n",
                    client.m_id);
            LOCK(client.cs_send);
            client.m_send_messages.emplace_back(request_tx_data_error);
            return;
        }
    }

    std::vector<uint8_t> witness_reserve_value;
    auto scriptWitness = block.vtx[0]->vin[0].scriptWitness;
    if (!scriptWitness.IsNull()) {
        std::copy(scriptWitness.stack[0].begin(), scriptWitness.stack[0].end(), std::back_inserter(witness_reserve_value));
    }
    std::vector<CTransactionRef> txs;
    if (block.vtx.size() > 0) {
        std::copy(block.vtx.begin() + 1, block.vtx.end(), std::back_inserter(txs));
    }

    node::Sv2RequestTransactionDataSuccessMsg request_tx_data_success{msg.m_template_id, std::move(witness_reserve_value), std::move(txs)};

    LogPrintLevel(BCLog::SV2, BCLog::Level::Debug, "Send 0x74 RequestTransactionData.Success to client id=%zu\n",
                    client.m_id);
    LOCK(client.cs_send);
    client.m_send_messages.emplace_back(request_tx_data_success);
}

void Sv2TemplateProvider::PruneBlockTemplateCache()
{
    AssertLockHeld(m_tp_mutex);

    // Allow a few seconds for clients to submit a block
    auto recent = GetTime<std::chrono::seconds>() - std::chrono::seconds(10);
    if (m_last_block_time > recent) return;
    // If the blocks prevout is not the tip's prevout, delete it.
    uint256 prev_hash = m_best_prev_hash;
    std::erase_if(m_block_template_cache, [prev_hash] (const auto& kv) {
        if (kv.second->getBlockHeader().hashPrevBlock != prev_hash) {
            return true;
        }
        return false;
    });
}

bool Sv2TemplateProvider::SendWork(Sv2Client& client, uint64_t template_id, BlockTemplate& block_template, bool future_template)
{
    CBlockHeader header{block_template.getBlockHeader()};

    node::Sv2NewTemplateMsg new_template{header,
                                        block_template.getCoinbaseTx(),
                                        block_template.getCoinbaseMerklePath(),
                                        block_template.getWitnessCommitmentIndex(),
                                        template_id,
                                        future_template};

    // TODO: use optimistic send instead of adding to the queue

    LogPrintLevel(BCLog::SV2, BCLog::Level::Debug, "Send 0x71 NewTemplate id=%lu future=%d to client id=%zu\n", template_id, future_template, client.m_id);
    LOCK(client.cs_send);
    client.m_send_messages.emplace_back(new_template);

    if (future_template) {
        node::Sv2SetNewPrevHashMsg new_prev_hash{header, template_id};
        LogPrintLevel(BCLog::SV2, BCLog::Level::Debug, "Send 0x72 SetNewPrevHash to client id=%zu\n", client.m_id);
        client.m_send_messages.emplace_back(new_prev_hash);
    }

    return true;
}

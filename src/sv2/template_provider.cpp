#include <sv2/template_provider.h>

#include <base58.h>
#include <consensus/merkle.h>
#include <crypto/hex_base.h>
#include <common/args.h>
#include <logging.h>
#include <sv2/noise.h>
#include <util/readwritefile.h>
#include <util/strencodings.h>
#include <util/thread.h>

Sv2TemplateProvider::Sv2TemplateProvider(interfaces::Mining& mining) : m_mining{mining}
{
    // TODO: persist static key
    CKey static_key;
    try {
        AutoFile{fsbridge::fopen(GetStaticKeyFile(), "rb")} >> static_key;
        LogPrintLevel(BCLog::SV2, BCLog::Level::Debug, "Reading cached static key from %s\n", fs::PathToString(GetStaticKeyFile()));
    } catch (const std::ios_base::failure&) {
        // File is not expected to exist the first time.
        // In the unlikely event that loading an existing key fails, create a new one.
    }
    if (!static_key.IsValid()) {
        static_key = GenerateRandomKey();
        try {
            AutoFile{fsbridge::fopen(GetStaticKeyFile(), "wb")} << static_key;
        } catch (const std::ios_base::failure&) {
            LogPrintLevel(BCLog::SV2, BCLog::Level::Error, "Error writing static key to %s\n", fs::PathToString(GetStaticKeyFile()));
            // Continue, because this is not a critical failure.
        }
        LogPrintLevel(BCLog::SV2, BCLog::Level::Debug, "Generated static key, saved to %s\n", fs::PathToString(GetStaticKeyFile()));
    }
    LogPrintLevel(BCLog::SV2, BCLog::Level::Info, "Static key: %s\n", HexStr(static_key.GetPubKey()));

   // Generate self signed certificate using (cached) authority key
    // TODO: skip loading authoritity key if -sv2cert is used

    // Load authority key if cached
    CKey authority_key;
    try {
        AutoFile{fsbridge::fopen(GetAuthorityKeyFile(), "rb")} >> authority_key;
    } catch (const std::ios_base::failure&) {
        // File is not expected to exist the first time.
        // In the unlikely event that loading an existing key fails, create a new one.
    }
    if (!authority_key.IsValid()) {
        authority_key = GenerateRandomKey();
        try {
            AutoFile{fsbridge::fopen(GetAuthorityKeyFile(), "wb")} << authority_key;
        } catch (const std::ios_base::failure&) {
            LogPrintLevel(BCLog::SV2, BCLog::Level::Error, "Error writing authority key to %s\n", fs::PathToString(GetAuthorityKeyFile()));
            // Continue, because this is not a critical failure.
        }
        LogPrintLevel(BCLog::SV2, BCLog::Level::Debug, "Generated authority key, saved to %s\n", fs::PathToString(GetAuthorityKeyFile()));
    }
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

    m_connman = std::make_unique<Sv2Connman>(TP_SUBPROTOCOL, static_key, m_authority_pubkey, certificate);
}

fs::path Sv2TemplateProvider::GetStaticKeyFile()
{
    return gArgs.GetDataDirNet() / "sv2_static_key";
}

fs::path Sv2TemplateProvider::GetAuthorityKeyFile()
{
    return gArgs.GetDataDirNet() / "sv2_authority_key";
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
    // Wait for the node chainstate to be ready if needed.
    auto tip{m_mining.waitTipChanged(uint256::ZERO)};
    Assert(tip.hash != uint256::ZERO);

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

    Timer timer(m_options.fee_check_interval);

    while (!m_flag_interrupt_sv2) {
        // We start with one template per client, which has an interface through
        // which we monitor for better templates.

        // TODO: give each client its own thread so they're treated equally
        //       and so that newly connected clients don't have to wait.
        std::optional<size_t> first_client_id{};
        m_connman->ForEachClient([this, &first_client_id](Sv2Client& client) {
            if (!client.m_coinbase_output_data_size_recv) return;

            if (!first_client_id) {
                first_client_id = client.m_id;
            }

            // Check if we already have a template interface for this client
            if (client.m_best_template_id != 0) {
                LOCK(m_tp_mutex);
                auto cached_template = m_block_template_cache.find(client.m_best_template_id);
                if (cached_template != m_block_template_cache.end()) return;
            }

            // Create block template and store interface reference
            // TODO: reuse template_id for clients with the same m_default_coinbase_tx_additional_output_size
            uint64_t template_id{WITH_LOCK(m_tp_mutex, return ++m_template_id;)};

            // https://github.com/bitcoin/bitcoin/pull/30356#issuecomment-2199791658
            uint32_t additional_coinbase_weight{(client.m_coinbase_tx_outputs_size + 100 + 0 + 2) * 4};

            const auto time_start{SteadyClock::now()};
            auto block_template = m_mining.createNewBlock(CScript(), {.use_mempool = true, .coinbase_max_additional_weight = additional_coinbase_weight});
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
            }

            if (!SendWork(client, template_id, *block_template, /*future_template=*/true)) {
                LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "Disconnecting client id=%zu\n",
                                client.m_id);
                client.m_disconnect_flag = true;
            }

            LOCK(m_tp_mutex);
            m_block_template_cache.insert({template_id, std::move(block_template)});
            client.m_best_template_id = template_id;
        });

        // Do not send templates with improved fees more frequently than the fee check interval
        const bool check_fees{timer.trigger()};
        bool new_template{false};

        // Delay event loop is no client if fully connected
        if (!first_client_id) std::this_thread::sleep_for(1000ms);

        // For the first connected client, wait for fees to rise.
        m_connman->ForEachClient([this, first_client_id, check_fees, &new_template](Sv2Client& client) {
            if (!first_client_id || client.m_id != first_client_id) return;
            Assert(client.m_coinbase_output_data_size_recv);

            std::shared_ptr<BlockTemplate> block_template = WITH_LOCK(m_tp_mutex, return m_block_template_cache.find(client.m_best_template_id)->second;);

            CAmount fee_delta{check_fees ? m_options.fee_delta : MAX_MONEY};

            // We give waitNext() a timeout of 1 second to prevent it from generating
            // new templates too quickly. During this wait we're not serving newly connected clients.
            // This can be cleaned up by having every client run its own thread.
            block_template = block_template->waitNext(fee_delta, MillisecondsDouble{1000});
            if (block_template) {
                new_template = true;

                uint256 prev_hash{block_template->getBlockHeader().hashPrevBlock};
                bool future_template{false};

                {
                    LOCK(m_tp_mutex);
                    if (prev_hash != m_best_prev_hash) {
                        future_template = true;
                        m_best_prev_hash = prev_hash;
                        // Does not need to be accurate
                        m_last_block_time = GetTime<std::chrono::seconds>();
                    }

                    ++m_template_id;
                }


                // Send it the updated template
                if (!SendWork(client, WITH_LOCK(m_tp_mutex, return m_template_id;), *block_template, future_template)) {
                    LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "Disconnecting client id=%zu\n",
                                    client.m_id);
                    client.m_disconnect_flag = true;
                }

                LOCK(m_tp_mutex);
                m_block_template_cache.insert({m_template_id, std::move(block_template)});
                client.m_best_template_id = m_template_id;

            }

        });

        if (new_template) {
            // And generate new temlates for the other clients
            m_connman->ForEachClient([this, first_client_id](Sv2Client& client) {
                if (!client.m_coinbase_output_data_size_recv) return;
                if (client.m_id == first_client_id.value()) return;

                std::shared_ptr<BlockTemplate> block_template = WITH_LOCK(m_tp_mutex, return m_block_template_cache.find(client.m_best_template_id)->second;);

                // Unconditionally make new template
                CAmount fee_delta{0};
                block_template = block_template->waitNext(fee_delta, MillisecondsDouble{0});
                if (Assert(block_template)) {
                    uint256 prev_hash{block_template->getBlockHeader().hashPrevBlock};
                    bool future_template{false};
                    {
                        LOCK(m_tp_mutex);
                        if (prev_hash != m_best_prev_hash) {
                            future_template = true;
                            m_best_prev_hash = prev_hash;
                            // Does not need to be accurate
                            m_last_block_time = GetTime<std::chrono::seconds>();
                        }

                        ++m_template_id;
                    }

                    // Send it the updated template
                    if (!SendWork(client, WITH_LOCK(m_tp_mutex, return m_template_id;), *block_template, future_template)) {
                        LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "Disconnecting client id=%zu\n",
                                        client.m_id);
                        client.m_disconnect_flag = true;
                    }

                    LOCK(m_tp_mutex);
                    m_block_template_cache.insert({m_template_id, std::move(block_template)});
                    client.m_best_template_id = m_template_id;
                }

            });
        }

        // Prune old templates and continue the loop.
        LOCK(m_tp_mutex);
        PruneBlockTemplateCache();

        // Take a very short break, the tests seem to need it.
        std::this_thread::sleep_for(1ms);
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
    client.m_send_messages.emplace_back(request_tx_data_success);
}

void Sv2TemplateProvider::SubmitSolution(node::Sv2SubmitSolutionMsg solution)
{
        LogPrintLevel(BCLog::SV2, BCLog::Level::Debug, "id=%lu version=%d, timestamp=%d, nonce=%d\n",
            solution.m_template_id,
            solution.m_version,
            solution.m_header_timestamp,
            solution.m_header_nonce
        );

        std::shared_ptr<BlockTemplate> block_template;
        {
            // We can't hold this lock until submitSolution() because it's
            // possible that the new block arrives via the p2p network at the
            // same time. That leads to a deadlock in g_best_block_mutex.
            LOCK(m_tp_mutex);
            auto cached_block_template = m_block_template_cache.find(solution.m_template_id);
            if (cached_block_template == m_block_template_cache.end()) {
                LogPrintLevel(BCLog::SV2, BCLog::Level::Debug, "Template with id=%lu is no longer in cache\n",
                solution.m_template_id);
                return;
            }
            /**
             * It's important to not delete this template from the cache in case
             * another solution is submitted for the same template later.
             *
             * This is very unlikely on mainnet, but not impossible. Many mining
             * devices may be working on the default pool template at the same
             * time and they may not update the new tip right away.
             *
             * The node will never broadcast the second block. It's marked
             * valid-headers in getchaintips. However a node or pool operator
             * may wish to manually inspect the block or keep it as a souvenir.
             * Additionally, because in Stratum v2 the block solution is sent
             * to both the pool node and the template provider node, it's
             * possibly they arrive out of order and two competing blocks propagate
             * on the network. In case of a reorg the node will be able to switch
             * faster because it already has (but not fully validated) the block.
             */
            block_template = cached_block_template->second;
        }

        block_template->submitSolution(solution.m_version, solution.m_header_timestamp, solution.m_header_nonce, solution.m_coinbase_tx);
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

    LogPrintLevel(BCLog::SV2, BCLog::Level::Debug, "Send 0x71 NewTemplate id=%lu future=%d to client id=%zu\n", template_id, future_template, client.m_id);
    client.m_send_messages.emplace_back(new_template);

    if (future_template) {
        node::Sv2SetNewPrevHashMsg new_prev_hash{header, template_id};
        LogPrintLevel(BCLog::SV2, BCLog::Level::Debug, "Send 0x72 SetNewPrevHash to client id=%zu\n", client.m_id);
        client.m_send_messages.emplace_back(new_prev_hash);
    }

    return true;
}

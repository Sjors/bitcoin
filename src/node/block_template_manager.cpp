// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/block_template_manager.h>

#include <node/miner.h>
#include <util/check.h>
#include <validation.h>

#include <vector>

namespace node {

BlockTemplateManager::BlockTemplateManager(CTxMemPool& mempool, ChainstateManager& chainman,
                                           BlockCreateOptions init_block_create_options)
    : m_mempool(mempool), m_chainman(chainman), m_init_block_create_options(std::move(init_block_create_options))
{
}

std::unique_ptr<CBlockTemplate> BlockTemplateManager::CreateNewTemplate(const BlockCreateOptions& options)
{
    return BlockAssembler{m_chainman.ActiveChainstate(), &m_mempool, options}.CreateNewBlock();
}

void TemplateSnapshot::RemoveChunk(const uint256& hash)
{
    auto tracked_chunk = template_chunks.find(hash);
    if (tracked_chunk == template_chunks.end()) return;
    total_fees -= tracked_chunk->second.feerate.fee;
    total_weight -= tracked_chunk->second.weight;
    total_sigops -= tracked_chunk->second.sigops_cost;
    Assume(chunks_by_feerate.erase({tracked_chunk->second.feerate, hash}) == 1);
    template_chunks.erase(tracked_chunk);
}

bool TemplateSnapshot::TrimToFit(int64_t needed_weight, int64_t needed_sigops, const FeePerWeight& incoming_feerate)
{
    const auto fits = [&](int64_t weight, int64_t sigops) {
        return weight + needed_weight < max_weight &&
               sigops + needed_sigops < MAX_BLOCK_SIGOPS_COST;
    };
    if (fits(total_weight, total_sigops)) return true;
    // Collect candidates first so unsuccessful trims leave the snapshot unchanged.
    std::vector<uint256> chunks_to_evict;
    int64_t simulated_weight = total_weight;
    int64_t simulated_sigops = total_sigops;
    for (auto feerate_entry = chunks_by_feerate.begin(); feerate_entry != chunks_by_feerate.end(); ++feerate_entry) {
        if (fits(simulated_weight, simulated_sigops)) break;
        if (ByRatio{incoming_feerate} <= ByRatio{feerate_entry->feerate}) break;
        const auto tracked_chunk = template_chunks.find(feerate_entry->hash);
        if (!Assume(tracked_chunk != template_chunks.end())) return false;
        simulated_weight -= tracked_chunk->second.weight;
        simulated_sigops -= tracked_chunk->second.sigops_cost;
        chunks_to_evict.push_back(feerate_entry->hash);
    }
    if (!fits(simulated_weight, simulated_sigops)) return false;
    for (const auto& hash : chunks_to_evict) {
        RemoveChunk(hash);
    }
    return true;
}

void TemplateSnapshot::AddChunk(const uint256& hash, const TrackedChunk& chunk)
{
    // Remove any previous entry so the feerate index and aggregate totals stay in sync.
    RemoveChunk(hash);
    template_chunks[hash] = chunk;
    total_fees += chunk.feerate.fee;
    total_weight += chunk.weight;
    total_sigops += chunk.sigops_cost;
    Assume(chunks_by_feerate.insert({chunk.feerate, hash}).second);
}

void TemplateSnapshot::SanityCheck() const
{
    Assume(template_chunks.size() == chunks_by_feerate.size());
    CAmount recomputed_fees{0};
    int64_t recomputed_weight{0};
    int64_t recomputed_sigops{0};
    for (const auto& [hash, chunk] : template_chunks) {
        Assume(chunks_by_feerate.contains({chunk.feerate, hash}));
        recomputed_fees += chunk.feerate.fee;
        recomputed_weight += chunk.weight;
        recomputed_sigops += chunk.sigops_cost;
    }
    for (const auto& feerate_entry : chunks_by_feerate) {
        const auto tracked_chunk = template_chunks.find(feerate_entry.hash);
        Assert(tracked_chunk != template_chunks.end());
        Assume(tracked_chunk->second.feerate == feerate_entry.feerate);
    }
    Assume(recomputed_fees == total_fees);
    Assume(recomputed_weight == total_weight);
    Assume(recomputed_sigops == total_sigops);
}

} // namespace node

// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/block_template_manager.h>

#include <consensus/consensus.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <kernel/types.h>
#include <node/miner.h>
#include <node/mining_args.h>
#include <util/check.h>
#include <util/hasher.h>
#include <validation.h>

#include <algorithm>
#include <numeric>
#include <vector>

namespace node {

BlockTemplateManager::BlockTemplateManager(CTxMemPool& mempool, ChainstateManager& chainman,
                                           BlockCreateOptions init_block_create_options)
    : m_mempool(mempool), m_chainman(chainman), m_init_block_create_options(std::move(init_block_create_options))
{
}

std::unique_ptr<CBlockTemplate> BlockTemplateManager::CreateNewTemplate(const BlockCreateOptions& options, uint64_t* tracking_id)
{
    // Keep the mempool unchanged between template assembly and snapshot
    // insertion, while avoiding holding m_mutex across CreateNewBlock().
    LOCK2(::cs_main, m_mempool.cs);
    auto block_template = BlockAssembler{m_chainman.CurrentChainstate(), &m_mempool, options}.CreateNewBlock();
    if (!tracking_id) return block_template;
    const auto resolved_options = FlattenMiningOptions(options);
    const auto min_fee_per_vsize = resolved_options.block_min_fee_rate->GetFeePerVSize();
    TemplateSnapshot snapshot;
    snapshot.tip_hash = block_template->block.hashPrevBlock;
    snapshot.options = resolved_options;
    snapshot.min_feerate = FeePerWeight{min_fee_per_vsize.fee, min_fee_per_vsize.size * WITNESS_SCALE_FACTOR};
    snapshot.max_weight = static_cast<int64_t>(*resolved_options.block_max_weight);
    snapshot.reserved_weight = static_cast<int64_t>(*resolved_options.block_reserved_weight);
    snapshot.total_weight = snapshot.reserved_weight;
    snapshot.reserved_sigops = static_cast<int64_t>(resolved_options.coinbase_output_max_additional_sigops);
    snapshot.total_sigops = snapshot.reserved_sigops;
    snapshot.height = block_template->m_height;
    snapshot.lock_time_cutoff = block_template->m_lock_time_cutoff;
    for (const auto& chunk : block_template->m_template_chunks) {
        auto wtxids{chunk.chunk_wtxids};
        snapshot.AddChunk(GetHashFromWitnesses(wtxids), {chunk.feerate, chunk.weight, chunk.sigops_cost});
    }
    // Baseline uses the same modified-fee basis as total_fees so the staleness
    // delta is zero at creation and reflects only later mempool fee inflow.
    snapshot.original_fees = snapshot.total_fees;
    LOCK(m_mutex);
    Assume(m_next_template_id != 0);
    *tracking_id = m_next_template_id++;
    m_template_snapshots[*tracking_id] = std::move(snapshot);
    return block_template;
}

// Connect and disconnect callbacks prune old-tip templates. They may run after
// a kernel tip wakeup creates a new-tip template, so do not clear all snapshots.
void BlockTemplateManager::BlockConnected(
    const kernel::ChainstateRole& role,
    const std::shared_ptr<const CBlock>& block,
    const CBlockIndex* /*unused*/)
{
    // Ignore block being connected to historical chain, not current chain.
    if (role.historical) return;
    const uint256& old_tip_hash = block->hashPrevBlock;
    LOCK(m_mutex);
    std::erase_if(m_template_snapshots, [&](const auto& entry) {
        return entry.second.tip_hash == old_tip_hash;
    });
}

void BlockTemplateManager::BlockDisconnected(
    const std::shared_ptr<const CBlock>& block,
    const CBlockIndex* /*unused*/)
{
    const uint256 old_tip_hash = block->GetHash();
    LOCK(m_mutex);
    std::erase_if(m_template_snapshots, [&](const auto& entry) {
        return entry.second.tip_hash == old_tip_hash;
    });
}

static int64_t ChunkWeight(const MemPoolChunk& chunk)
{
    return std::accumulate(chunk.m_transactions.begin(), chunk.m_transactions.end(), int64_t{0},
                           [](int64_t sum, const auto& tx) { return sum + GetTransactionWeight(*tx); });
}

static bool IsFinalChunk(const MemPoolChunk& chunk, int height, int64_t lock_time_cutoff)
{
    return std::all_of(chunk.m_transactions.begin(), chunk.m_transactions.end(),
                       [&](const auto& tx) { return IsFinalTx(*tx, height, lock_time_cutoff); });
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
    Assume(reserved_weight + recomputed_weight == total_weight);
    Assume(reserved_sigops + recomputed_sigops == total_sigops);
}

void BlockTemplateManager::MempoolUpdated(const MemPoolChunksUpdate& mempool_chunks)
{
    if (mempool_chunks.reason == MemPoolRemovalReason::BLOCK ||
        mempool_chunks.reason == MemPoolRemovalReason::CONFLICT) {
        // Chain transitions prune tracked templates built on the old tip via
        // BlockConnected/BlockDisconnected.
        return;
    }
    LOCK(m_mutex);
    if (m_template_snapshots.empty()) return;

    for (const auto& chunk : mempool_chunks.old_chunks) {
        const auto& hash = *Assume(chunk.m_chunk_hash);
        for (auto& [_, snapshot] : m_template_snapshots) {
            snapshot.RemoveChunk(hash);
        }
    }
    for (const auto& chunk : mempool_chunks.new_chunks) {
        const auto& hash = *Assume(chunk.m_chunk_hash);
        const int64_t weight = ChunkWeight(chunk);
        for (auto& [_, snapshot] : m_template_snapshots) {
            if (!snapshot.options.use_mempool) continue;
            // Mempool add callbacks can be delivered after a snapshot already
            // tracks the chunk. Treat duplicate adds as idempotent before
            // TrimToFit(), otherwise the incoming chunk's weight could be
            // considered twice and unnecessarily stage evictions.
            if (snapshot.template_chunks.contains(hash)) continue;
            if (ByRatio{chunk.m_fee_rate} < ByRatio{snapshot.min_feerate}) continue;
            if (!IsFinalChunk(chunk, snapshot.height, snapshot.lock_time_cutoff)) continue;
            if (snapshot.TrimToFit(weight, chunk.m_sigops_cost, chunk.m_fee_rate)) {
                snapshot.AddChunk(hash, {chunk.m_fee_rate, weight, chunk.m_sigops_cost});
            }
        }
    }
}

bool BlockTemplateManager::IsTrackingFeeInflow(uint64_t template_id) const
{
    LOCK(m_mutex);
    return m_template_snapshots.contains(template_id);
}

void BlockTemplateManager::StopTrackingFeeInflow(uint64_t template_id)
{
    LOCK(m_mutex);
    m_template_snapshots.erase(template_id);
}

bool BlockTemplateManager::IsStale(const BlockCreateOptions& options,
                                   uint64_t template_id,
                                   CAmount fee_threshold) const
{
    LOCK(m_mutex);
    const auto snapshot = m_template_snapshots.find(template_id);
    if (snapshot == m_template_snapshots.end()) return false;
    if (snapshot->second.options != FlattenMiningOptions(options)) return false;
    const CAmount fee_delta = snapshot->second.total_fees - snapshot->second.original_fees;
    return fee_delta >= fee_threshold;
}

void BlockTemplateManager::SanityCheck() const
{
    LOCK(m_mutex);
    for (const auto& [_, snapshot] : m_template_snapshots) {
        snapshot.SanityCheck();
        Assume(snapshot.total_fees >= 0);
        Assume(snapshot.total_weight >= 0);
        if (snapshot.template_chunks.empty()) {
            Assume(snapshot.total_weight <= snapshot.max_weight);
        } else {
            Assume(snapshot.total_weight < snapshot.max_weight);
        }
        Assume(snapshot.total_sigops >= 0);
        if (snapshot.template_chunks.empty()) {
            Assume(snapshot.total_sigops <= MAX_BLOCK_SIGOPS_COST);
        } else {
            Assume(snapshot.total_sigops < MAX_BLOCK_SIGOPS_COST);
        }
    }
}

} // namespace node

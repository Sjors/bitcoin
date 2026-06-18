// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_BLOCK_TEMPLATE_MANAGER_H
#define BITCOIN_NODE_BLOCK_TEMPLATE_MANAGER_H

#include <consensus/amount.h>
#include <node/mining_types.h>
#include <uint256.h>
#include <util/feefrac.h>

#include <cstdint>
#include <map>
#include <memory>
#include <set>

class ChainstateManager;
class CTxMemPool;

namespace node {
struct CBlockTemplate;

/** Data structure for incrementally tracking chunks from a block template.
 *
 * Chunks are indexed by hash for mempool-removal updates, and by feerate for
 * trimming when a higher-feerate chunk arrives. The feerate index is maintained
 * incrementally, avoiding a full sort on every TrimToFit() call.
 *
 * Invariant: template_chunks and chunks_by_feerate contain the same chunk
 * hashes, and total_fees/total_weight/total_sigops are their aggregate totals.
 */
struct TemplateSnapshot {
    /** Chunk metadata captured from the template: adjusted feerate, weight,
     *  and sigops. */
    struct TrackedChunk {
        FeePerWeight feerate;
        int64_t weight;
        int64_t sigops_cost;
    };
    /** Feerate index key. The hash distinguishes chunks with equal feerates
     *  and allows direct erasure using metadata from template_chunks. */
    struct FeerateIndexEntry {
        FeePerWeight feerate;
        uint256 hash;
        friend bool operator<(const FeerateIndexEntry& left, const FeerateIndexEntry& right)
        {
            const auto feerate_order = ByRatio{left.feerate} <=> ByRatio{right.feerate};
            return feerate_order != 0 ? feerate_order < 0 : left.hash < right.hash;
        }
    };
    /** Owns tracked chunk metadata keyed by chunk hash. */
    std::map<uint256, TrackedChunk> template_chunks;
    /** Keeps chunks sorted so TrimToFit() can scan lowest-feerate chunks first. */
    std::set<FeerateIndexEntry> chunks_by_feerate;
    /** Minimum feerate accepted by the original template. */
    FeePerWeight min_feerate;
    /** Exclusive block weight limit used when deciding if new chunks fit. */
    int64_t max_weight{0};
    /** Aggregate fees of all currently tracked chunks. */
    CAmount total_fees{0};
    /** Aggregate weight of all currently tracked chunks. */
    int64_t total_weight{0};
    /** Aggregate sigops cost of all currently tracked chunks. */
    int64_t total_sigops{0};
    /** Chain height used for finality checks against new chunks. */
    int height{0};
    /** Median-time-past cutoff used for finality checks against new chunks. */
    int64_t lock_time_cutoff{0};
    /** Remove a chunk by hash in O(log n). */
    void RemoveChunk(const uint256& hash);
    /** Add a chunk in O(log n). */
    void AddChunk(const uint256& hash, const TrackedChunk& chunk);
    /** Evict lowest-feerate chunks to make room for @p needed_weight and @p needed_sigops.
     *  Only commits evictions if the chunk will fit afterward.
     *  Returns true if the incoming chunk fits after eviction.
     *  Runs in O(s log n), where s is the number of scanned chunks. */
    bool TrimToFit(int64_t needed_weight, int64_t needed_sigops, const FeePerWeight& incoming_feerate);
    /** Verify the chunk indexes and cached fee, weight, and sigops totals.
     *  Runs in O(n log n). */
    void SanityCheck() const;
};

/** Creates block templates. */
class BlockTemplateManager
{
private:
    CTxMemPool& m_mempool;
    ChainstateManager& m_chainman;
    const BlockCreateOptions m_init_block_create_options;

public:
    explicit BlockTemplateManager(CTxMemPool& mempool,
                                  ChainstateManager& chainman,
                                  BlockCreateOptions init_block_create_options = {});

    /** @return a copy of the block create options set during node init. */
    BlockCreateOptions GetInitBlockCreateOptions() const { return m_init_block_create_options; }

    /** Create a fresh block template. */
    std::unique_ptr<CBlockTemplate> CreateNewTemplate(const BlockCreateOptions& options);
};
} // namespace node

#endif // BITCOIN_NODE_BLOCK_TEMPLATE_MANAGER_H

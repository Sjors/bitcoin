// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txmempool.h>

#include <chain.h>
#include <cluster_linearize.h>
#include <coins.h>
#include <common/system.h>
#include <consensus/consensus.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <logging.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <reverse_iterator.h>
#include <util/check.h>
#include <util/moneystr.h>
#include <util/overflow.h>
#include <util/result.h>
#include <util/time.h>
#include <util/trace.h>
#include <util/translation.h>
#include <validationinterface.h>

#include <cmath>
#include <numeric>
#include <optional>
#include <string_view>
#include <utility>

bool TestLockPointValidity(CChain& active_chain, const LockPoints& lp)
{
    AssertLockHeld(cs_main);
    // If there are relative lock times then the maxInputBlock will be set
    // If there are no relative lock times, the LockPoints don't depend on the chain
    if (lp.maxInputBlock) {
        // Check whether active_chain is an extension of the block at which the LockPoints
        // calculation was valid.  If not LockPoints are no longer valid
        if (!active_chain.Contains(lp.maxInputBlock)) {
            return false;
        }
    }

    // LockPoints still valid
    return true;
}

void CTxMemPool::UpdateClusterForDescendants(txiter updateIt)
{
    AssertLockHeld(cs);
    CTxMemPoolEntry::Children children = updateIt->GetMemPoolChildrenConst();
    std::vector<Cluster *> clusters_to_merge{updateIt->m_cluster};
    {
        WITH_FRESH_EPOCH(m_epoch);
        visited(updateIt->m_cluster);
        cachedInnerUsage -= updateIt->m_cluster->GetMemoryUsage();
        for (auto child : children) {
            if (!visited(child.get().m_cluster)) {
                clusters_to_merge.push_back(child.get().m_cluster);
                cachedInnerUsage -= child.get().m_cluster->GetMemoryUsage();
            }
        }
    }
    if (clusters_to_merge.size() > 1) {
        // Merge the other clusters into this one, but keep this cluster as
        // first so that it's topologically sound.
        clusters_to_merge[0]->Merge(clusters_to_merge.begin()+1, clusters_to_merge.end(), true);
        // Need to delete the other clusters.
        for (auto it=clusters_to_merge.begin()+1; it!= clusters_to_merge.end(); ++it) {
            m_cluster_map.erase((*it)->m_id);
        }
        // Note: we cannot re-sort the cluster here, because (a) we are not yet
        // finished merging connected clusters together, so some parents may be
        // missing, and (b) the cluster may be too large. Sorting should happen
        // only after all clustering is complete, and the clusters have been
        // trimmed down to our cluster count limit.
        clusters_to_merge[0]->Rechunk();
        // Add some assertion that topology is still valid?
    }
    cachedInnerUsage += clusters_to_merge[0]->GetMemoryUsage();
    return;
}

void CTxMemPool::UpdateTransactionsFromBlock(const std::vector<uint256>& vHashesToUpdate)
{
    AssertLockHeld(cs);

    // Iterate in reverse, so that whenever we are looking at a transaction
    // we are sure that all in-mempool descendants have already been processed.
    for (const uint256 &hash : reverse_iterate(vHashesToUpdate)) {
        // calculate children from mapNextTx
        txiter it = mapTx.find(hash);
        if (it == mapTx.end()) {
            continue;
        }
        auto iter = mapNextTx.lower_bound(COutPoint(hash, 0));
        // First calculate the children, and update CTxMemPoolEntry::m_children to
        // include them, and update their CTxMemPoolEntry::m_parents to include this tx.
        // we cache the in-mempool children to avoid duplicate updates
        {
            WITH_FRESH_EPOCH(m_epoch);
            for (; iter != mapNextTx.end() && iter->first->hash == hash; ++iter) {
                const uint256 &childHash = iter->second->GetHash();
                txiter childIter = mapTx.find(childHash);
                assert(childIter != mapTx.end());
                // We can skip updating entries we've encountered before or that
                // are in the block (which are already accounted for).
                if (!visited(childIter)) {
                    UpdateChild(it, childIter, true);
                    UpdateParent(childIter, it, true);
                }
            }
        }
    }

    // Fix clusters - start by merging, then re-sort after merges are complete.
    for (const uint256& hash : reverse_iterate(vHashesToUpdate)) {
        txiter it = mapTx.find(hash);
        if (it == mapTx.end()) continue;
        UpdateClusterForDescendants(it);
    }
    std::vector<Cluster *> unique_clusters_from_block;
    {
        WITH_FRESH_EPOCH(m_epoch);
        for (const uint256& hash : reverse_iterate(vHashesToUpdate)) {
            txiter it = mapTx.find(hash);
            if (it == mapTx.end()) continue;
            if (!visited(it->m_cluster)) {
                unique_clusters_from_block.push_back(it->m_cluster);
            }
        }
    }
    for (Cluster *cluster : unique_clusters_from_block) {
        // If the cluster is too big, then we need to limit it by
        // evicting transactions and then re-calculate the cluster (it
        // may have split).  Otherwise, just sort.
        if (cluster->m_tx_count > m_limits.cluster_count || cluster->m_tx_size > m_limits.cluster_size_vbytes) {
            // Remove the last transaction in the cluster.
            cachedInnerUsage -= cluster->GetMemoryUsage();
            while (cluster->m_tx_count > m_limits.cluster_count ||
                    cluster->m_tx_size > m_limits.cluster_size_vbytes) {
                UpdateForRemoveFromMempool({mapTx.iterator_to(cluster->GetLastTransaction())});
                removeUnchecked(mapTx.iterator_to(cluster->GetLastTransaction()), MemPoolRemovalReason::SIZELIMIT);
            }
            RecalculateClusterAndMaybeSort(cluster, true);
        } else {
            // Sort() can change the memory usage of the cluster
            cachedInnerUsage -= cluster->GetMemoryUsage();
            cluster->Sort();
            cachedInnerUsage += cluster->GetMemoryUsage();
        }
    }
}

CTxMemPool::Entries CTxMemPool::CalculateAncestors(const Entries& parents) const
{
    Entries ancestors{}, work_queue{};

    WITH_FRESH_EPOCH(m_epoch);
    for (auto p : parents) {
        if (!visited(p)) {
            work_queue.push_back(p);
        }
    }

    while (!work_queue.empty()) {
        auto it = work_queue.back();
        work_queue.pop_back();
        ancestors.push_back(it);

        for (auto parent : it->GetMemPoolParentsConst()) {
            auto parent_it = mapTx.iterator_to(parent);
            if (!visited(parent_it)) {
                work_queue.push_back(parent_it);
            }
        }
    }

    return ancestors;
}

bool CTxMemPool::CheckPackageLimits(const Package& package,
                                    const int64_t total_vsize,
                                    std::string &errString) const
{
    CTxMemPoolEntry::Parents staged_ancestors;
    for (const auto& tx : package) {
        for (const auto& input : tx->vin) {
            std::optional<txiter> piter = GetIter(input.prevout.hash);
            if (piter) {
                staged_ancestors.insert(**piter);
            }
        }
    }
    auto cluster_result{CheckClusterSizeLimit(total_vsize, package.size(), m_limits, staged_ancestors)};
    if (!cluster_result) {
        errString = util::ErrorString(cluster_result).original;
        return false;
    }
    return true;
}

CTxMemPool::Entries CTxMemPool::CalculateParents(const CTxMemPoolEntry &entry) const
{
    Entries ret;
    {
        WITH_FRESH_EPOCH(m_epoch);
        for (const CTxIn &txin : entry.GetTx().vin) {
            std::optional<txiter> piter = GetIter(txin.prevout.hash);
            if (piter && !visited(*piter)) {
                ret.push_back(*piter);
            }
        }
    }
    return ret;
}

bool CTxMemPool::BuildClusterForTransaction(CTxMemPoolEntry& entry, const setEntries& all_conflicts, const Limits& limits, Cluster& temp_cluster)
{
    // Start by calculating all parents, which much be in the same cluster as entry.
    // Then, we repeat by walking all children of those parents, and add those to the cluster.
    // For each child, walk its parents, and repeat until we have nothing left to walk, or until we exceed some limit.
    // Return the built cluster.
    temp_cluster.Clear();
    temp_cluster.m_chunks.emplace_back(0, 0);
    std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> work_queue;

    // Start by calculating the parents of this transaction, and adding them to the work queue.
    {
        Entries parents = CalculateParents(entry);
        // The parents need to be in the CTxMemPoolEntry for the Sort() below
        // to work.
        for (auto it : parents) {
            entry.GetMemPoolParents().insert(*it);
        }

        WITH_FRESH_EPOCH(m_epoch);

        for (auto parent_iter : entry.GetMemPoolParentsConst()) {
            work_queue.push_back(parent_iter);
            visited(parent_iter.get());
        }
        while (!work_queue.empty()) {
            auto next_entry = work_queue.back();
            work_queue.pop_back();
            if (all_conflicts.count(mapTx.iterator_to(next_entry))) {
                // Skip entries that are in the conflicts list
                continue;
            }
            temp_cluster.m_chunks[0].txs.push_back(next_entry);
            temp_cluster.m_tx_count++;
            temp_cluster.m_tx_size += next_entry.get().GetTxSize();
            if (temp_cluster.m_tx_count > limits.cluster_count || temp_cluster.m_tx_size > limits.cluster_size_vbytes) {
                return false;
            }
            auto next_children = next_entry.get().GetMemPoolChildrenConst();
            for (auto descendant : next_children) {
                if (!visited(descendant.get())) {
                    work_queue.push_back(descendant);
                }
            }
            auto next_parents = next_entry.get().GetMemPoolParentsConst();
            for (auto parent : next_parents) {
                if (!visited(parent.get())) {
                    work_queue.push_back(parent);
                }
            }
        }
    }
    temp_cluster.m_chunks[0].txs.emplace_back(entry);
    temp_cluster.m_tx_count++;
    temp_cluster.m_tx_size += entry.GetTxSize();

    if (temp_cluster.m_tx_count > limits.cluster_count || temp_cluster.m_tx_size > limits.cluster_size_vbytes) {
        return false;
    }

    temp_cluster.Sort(false);

    // Undo the changes we made to the entry.
    entry.GetMemPoolParents().clear();

    return true;
}

util::Result<bool> CTxMemPool::CheckClusterSizeLimit(int64_t entry_size, size_t entry_count,
        const Limits& limits, const CTxMemPoolEntry::Parents& all_parents) const
{
    int64_t total_cluster_count = entry_count;
    int64_t total_cluster_vbytes = entry_size;

    {
        WITH_FRESH_EPOCH(m_epoch);
        for (auto ancestor_iter : all_parents) {
            if (!visited(ancestor_iter.get().m_cluster)) {
                total_cluster_count += ancestor_iter.get().m_cluster->m_tx_count;
                total_cluster_vbytes += ancestor_iter.get().m_cluster->m_tx_size;
                // Short-circuit the calculation if we're definitely going to exceed the cluster limits.
                if (total_cluster_count > limits.cluster_count || total_cluster_vbytes > limits.cluster_size_vbytes) {
                    break;
                }
            }
        }
    }
    if (total_cluster_count > limits.cluster_count) {
        return util::Error{Untranslated(strprintf("too many unconfirmed transactions in the cluster [limit: %ld]", limits.cluster_count))};
    }
    if (total_cluster_vbytes > limits.cluster_size_vbytes) {
        return util::Error{Untranslated(strprintf("exceeds cluster size limit [limit: %d]", limits.cluster_size_vbytes))};
    }
    return true;
}

CTxMemPool::Entries CTxMemPool::CalculateMemPoolAncestors(const CTxMemPoolEntry& entry, bool fSearchForParents) const
{
    Entries parents;
    if (fSearchForParents) {
        parents = CalculateParents(entry);
    } else {
        for (auto p : entry.GetMemPoolParentsConst()) {
            parents.push_back(mapTx.iterator_to(p.get()));
        }
    }

    return CalculateAncestors(parents);
}

CTxMemPool::setEntries CTxMemPool::CalculateMemPoolAncestorsSlow(
    const CTxMemPoolEntry &entry,
    bool fSearchForParents /* = true */) const
{
    auto ancestors = CalculateMemPoolAncestors(entry, fSearchForParents);

    setEntries ret;
    ret.insert(ancestors.begin(), ancestors.end());
    return ret;
}

util::Result<CFeeRate> CTxMemPool::CalculateMiningScoreOfReplacementTx(CTxMemPoolEntry& entry, CAmount modified_fee, const setEntries& all_conflicts, const Limits& limits)
{
    Cluster temp_cluster(0, this);

    // We sort based on the modified fee.
    entry.UpdateModifiedFee(modified_fee - entry.GetFee());
    if (!BuildClusterForTransaction(entry, all_conflicts, limits, temp_cluster)) {
        // Check to see which limit was violated.
        if (temp_cluster.m_tx_count > limits.cluster_count) {
            return util::Error{Untranslated(strprintf("too many unconfirmed transactions in the cluster [limit: %ld]", limits.cluster_count))};
        } else if (temp_cluster.m_tx_size > limits.cluster_size_vbytes) {
            return util::Error{Untranslated(strprintf("exceeds cluster size limit [limit: %ld]", limits.cluster_size_vbytes))};
        } else {
            return util::Error{Untranslated("unknown error")};
        }
    }
    entry.UpdateModifiedFee(entry.GetFee() - modified_fee);

    // Return the feerate we calculated.
    CAmount chunk_fees{0};
    int64_t chunk_size{0};

    for (const auto& chunk : temp_cluster.m_chunks) {
        for (auto& txentry : chunk.txs) {
            if (&(txentry.get()) == &entry) {
                chunk_fees = chunk.fee;
                chunk_size = chunk.size;
                break;
            }
        }
    }
    return CFeeRate(chunk_fees, chunk_size);
}

void CTxMemPool::UpdateParentsOf(bool add, txiter it)
{
    const CTxMemPoolEntry::Parents& parents = it->GetMemPoolParentsConst();
    // add or remove this tx as a child of each parent
    for (const CTxMemPoolEntry& parent : parents) {
        UpdateChild(mapTx.iterator_to(parent), it, add);
    }
}

void CTxMemPool::UpdateChildrenForRemoval(txiter it)
{
    const CTxMemPoolEntry::Children& children = it->GetMemPoolChildrenConst();
    for (const CTxMemPoolEntry& updateIt : children) {
        UpdateParent(mapTx.iterator_to(updateIt), it, false);
    }
}

void CTxMemPool::UpdateForRemoveFromMempool(const setEntries &entriesToRemove)
{
    // Sever the parent/child links for transactions we're removing
    for (txiter removeIt : entriesToRemove) {
        UpdateParentsOf(false, removeIt);
        UpdateChildrenForRemoval(removeIt);
    }
}

CTxMemPool::CTxMemPool(const Options& opts)
    : m_check_ratio{opts.check_ratio},
      minerPolicyEstimator{opts.estimator},
      m_max_size_bytes{opts.max_size_bytes},
      m_expiry{opts.expiry},
      m_incremental_relay_feerate{opts.incremental_relay_feerate},
      m_min_relay_feerate{opts.min_relay_feerate},
      m_dust_relay_feerate{opts.dust_relay_feerate},
      m_permit_bare_multisig{opts.permit_bare_multisig},
      m_max_datacarrier_bytes{opts.max_datacarrier_bytes},
      m_require_standard{opts.require_standard},
      m_full_rbf{opts.full_rbf},
      m_limits{opts.limits}
{
}

bool CTxMemPool::isSpent(const COutPoint& outpoint) const
{
    LOCK(cs);
    return mapNextTx.count(outpoint);
}

unsigned int CTxMemPool::GetTransactionsUpdated() const
{
    return nTransactionsUpdated;
}

void CTxMemPool::AddTransactionsUpdated(unsigned int n)
{
    nTransactionsUpdated += n;
}

void CTxMemPool::addUnchecked(const CTxMemPoolEntry &entry, bool validFeeEstimate)
{
    // Add to memory pool without checking anything.
    // Used by AcceptToMemoryPool(), which DOES do
    // all the appropriate checks.
    indexed_transaction_set::iterator newit = mapTx.insert(entry).first;

    // Update transaction for any feeDelta created by PrioritiseTransaction
    CAmount delta{0};
    ApplyDelta(entry.GetTx().GetHash(), delta);
    // The following call to UpdateModifiedFee assumes no previous fee modifications
    Assume(entry.GetFee() == entry.GetModifiedFee());
    if (delta) {
        mapTx.modify(newit, [&delta](CTxMemPoolEntry& e) { e.UpdateModifiedFee(delta); });
    }

    // Update cachedInnerUsage to include contained transaction's usage.
    // (When we update the entry for in-mempool parents, memory usage will be
    // further updated.)
    cachedInnerUsage += entry.DynamicMemoryUsage();

    const CTransaction& tx = newit->GetTx();
    std::set<uint256> setParentTransactions;
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        mapNextTx.insert(std::make_pair(&tx.vin[i].prevout, &tx));
        setParentTransactions.insert(tx.vin[i].prevout.hash);
    }
    // Don't bother worrying about child transactions of this one.
    // Normal case of a new transaction arriving is that there can't be any
    // children, because such children would be orphans.
    // An exception to that is if a transaction enters that used to be in a block.
    // In that case, our disconnect block logic will call UpdateTransactionsFromBlock
    // to clean up the mess we're leaving here.

    // Add parents to parent set for this transaction.
    for (const auto& pit : GetIterSet(setParentTransactions)) {
        UpdateParent(newit, pit, true);
    }
    // Update this transaction's in-mempool parents with information about this
    // tx
    UpdateParentsOf(true, newit);

    nTransactionsUpdated++;
    totalTxSize += entry.GetTxSize();
    m_total_fee += entry.GetFee();
    if (minerPolicyEstimator) {
        minerPolicyEstimator->processTransaction(entry, validFeeEstimate);
    }

    vTxHashes.emplace_back(tx.GetWitnessHash(), newit);
    newit->vTxHashesIdx = vTxHashes.size() - 1;

    // Figure out which cluster this transaction belongs to.
    auto iterset = GetIterSet(setParentTransactions);
    std::vector<Cluster*> clusters_to_merge;
    {
        WITH_FRESH_EPOCH(m_epoch);
        for (auto parentit : iterset) {
            if (!visited(parentit->m_cluster)) {
                clusters_to_merge.push_back(parentit->m_cluster);
            }
        }
    }

    // Merge all the clusters together.
    if (clusters_to_merge.size() == 0) {
        // No parents, make a new cluster.
        newit->m_cluster = AssignCluster();
        newit->m_cluster->AddTransaction(*newit, true);
        cachedInnerUsage += newit->m_cluster->GetMemoryUsage();
    } else if (clusters_to_merge.size() == 1) {
        cachedInnerUsage -= clusters_to_merge[0]->GetMemoryUsage();
        // Only one parent cluster: add to it.
        clusters_to_merge[0]->AddTransaction(*newit, true);
        cachedInnerUsage += clusters_to_merge[0]->GetMemoryUsage();
    } else {
        cachedInnerUsage -= clusters_to_merge[0]->GetMemoryUsage();
        clusters_to_merge[0]->Merge(clusters_to_merge.begin()+1, clusters_to_merge.end(), false);
        // Add this transaction to the cluster.
        clusters_to_merge[0]->AddTransaction(*newit, true);
        // Need to delete the other clusters.
        for (auto it=clusters_to_merge.begin()+1; it != clusters_to_merge.end(); ++it) {
            cachedInnerUsage -= (*it)->GetMemoryUsage();
            m_cluster_map.erase((*it)->m_id);
        }
        cachedInnerUsage += clusters_to_merge[0]->GetMemoryUsage();
    }

    TRACE3(mempool, added,
        entry.GetTx().GetHash().data(),
        entry.GetTxSize(),
        entry.GetFee()
    );
}

void CTxMemPool::removeUnchecked(txiter it, MemPoolRemovalReason reason)
{
    // We increment mempool sequence value no matter removal reason
    // even if not directly reported below.
    uint64_t mempool_sequence = GetAndIncrementSequence();

    if (reason != MemPoolRemovalReason::BLOCK) {
        // Notify clients that a transaction has been removed from the mempool
        // for any reason except being included in a block. Clients interested
        // in transactions included in blocks can subscribe to the BlockConnected
        // notification.
        GetMainSignals().TransactionRemovedFromMempool(it->GetSharedTx(), reason, mempool_sequence);
    }
    TRACE5(mempool, removed,
        it->GetTx().GetHash().data(),
        RemovalReasonToString(reason).c_str(),
        it->GetTxSize(),
        it->GetFee(),
        std::chrono::duration_cast<std::chrono::duration<std::uint64_t>>(it->GetTime()).count()
    );

    const uint256 hash = it->GetTx().GetHash();
    for (const CTxIn& txin : it->GetTx().vin)
        mapNextTx.erase(txin.prevout);

    RemoveUnbroadcastTx(hash, true /* add logging because unchecked */ );

    if (vTxHashes.size() > 1) {
        vTxHashes[it->vTxHashesIdx] = std::move(vTxHashes.back());
        vTxHashes[it->vTxHashesIdx].second->vTxHashesIdx = it->vTxHashesIdx;
        vTxHashes.pop_back();
        if (vTxHashes.size() * 2 < vTxHashes.capacity())
            vTxHashes.shrink_to_fit();
    } else
        vTxHashes.clear();

    // Remove this transaction from its cluster
    it->m_cluster->RemoveTransaction(*it);

    totalTxSize -= it->GetTxSize();
    m_total_fee -= it->GetFee();
    cachedInnerUsage -= it->DynamicMemoryUsage();
    cachedInnerUsage -= memusage::DynamicUsage(it->GetMemPoolParentsConst()) + memusage::DynamicUsage(it->GetMemPoolChildrenConst());
    mapTx.erase(it);
    nTransactionsUpdated++;
    if (minerPolicyEstimator) {minerPolicyEstimator->removeTx(hash, false);}
}

// Calculates descendants of given entry and adds to setDescendants.
void CTxMemPool::CalculateDescendantsSlow(txiter entryit, setEntries& setDescendants) const
{
    auto descendants = CalculateDescendants({entryit});
    setDescendants.insert(descendants.begin(), descendants.end());
}

CTxMemPool::Entries CTxMemPool::CalculateDescendants(Entries txs) const
{
    Entries result{}, work_queue{};

    WITH_FRESH_EPOCH(m_epoch);
    for (auto it: txs) {
        if (!visited(it)) {
            work_queue.push_back(it);
        }
    }

    while (!work_queue.empty()) {
        auto it = work_queue.back();
        work_queue.pop_back();
        result.push_back(it);
        for (auto& child: it->GetMemPoolChildrenConst()) {
            if (!visited(child)) {
                work_queue.push_back(mapTx.iterator_to(child));
            }
        }
    }
    return result;
}

void CTxMemPool::removeRecursive(const CTransaction &origTx, MemPoolRemovalReason reason)
{
    // Remove transaction from memory pool
    AssertLockHeld(cs);
    Entries txToRemove;
    txiter origit = mapTx.find(origTx.GetHash());

    {
        WITH_FRESH_EPOCH(m_epoch);
        if (origit != mapTx.end()) {
            visited(origit);
            txToRemove.push_back(origit);
        } else {
            // When recursively removing but origTx isn't in the mempool
            // be sure to remove any children that are in the pool. This can
            // happen during chain re-orgs if origTx isn't re-accepted into
            // the mempool for any reason.
            for (unsigned int i = 0; i < origTx.vout.size(); i++) {
                auto it = mapNextTx.find(COutPoint(origTx.GetHash(), i));
                if (it == mapNextTx.end())
                    continue;
                txiter nextit = mapTx.find(it->second->GetHash());
                assert(nextit != mapTx.end());
                if (!visited(nextit)) {
                    txToRemove.push_back(nextit);
                }
            }
        }
    }
    setEntries setAllRemoves;
    auto all_removes = CalculateDescendants(txToRemove);

    setAllRemoves.insert(all_removes.begin(), all_removes.end());

    RemoveStaged(setAllRemoves, false, reason);
}

Cluster* CTxMemPool::AssignCluster()
{
    auto new_cluster = std::make_unique<Cluster>(m_next_cluster_id++, this);
    Cluster* ret = new_cluster.get(); // XXX No one is going to like this.
    m_cluster_map[new_cluster->m_id] = std::move(new_cluster);
    return ret;
}

// When transactions are removed from a cluster, the cluster might get split
// into smaller clusters.
void CTxMemPool::RecalculateClusterAndMaybeSort(Cluster *cluster, bool sort)
{
    // TODO: if the common case involves no cluster splitting, can we short
    // circuit the work here somehow?

    // Wipe cluster assignments.
    std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> txs;
    for (auto& chunk : cluster->m_chunks) {
        for (auto& txentry: chunk.txs) {
            txentry.get().m_cluster = nullptr;
            txs.push_back(txentry);
        }
    }
    cluster->Clear();

    // The first transaction gets to stay in the existing cluster.
    bool first = true;
    for (auto& txentry : txs) {
        if (txentry.get().m_cluster == nullptr) {
            if (first) {
                txentry.get().m_cluster = cluster;
                first = false;
            } else {
                txentry.get().m_cluster = AssignCluster();
            }
            txentry.get().m_cluster->AddTransaction(txentry.get(), false);
            // We need to label all transactions connected to this one as
            // being in the same cluster.
            {
                WITH_FRESH_EPOCH(m_epoch);
                auto children = txentry.get().GetMemPoolChildrenConst();
                std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> work_queue;
                for (auto entry : children) {
                    work_queue.push_back(entry);
                    visited(entry.get());
                }

                while (!work_queue.empty()) {
                    auto next_entry = work_queue.back();
                    work_queue.pop_back();
                    next_entry.get().m_cluster = txentry.get().m_cluster;

                    auto next_children = next_entry.get().GetMemPoolChildrenConst();
                    for (auto& descendant : next_children) {
                        if (!visited(descendant.get())) {
                            work_queue.push_back(descendant);
                        }
                    }
                    auto next_parents = next_entry.get().GetMemPoolParentsConst();
                    for (auto& ancestor : next_parents) {
                        if (!visited(ancestor.get())) {
                            work_queue.push_back(ancestor);
                        }
                    }
                }
            }
        } else {
            // If we already have a cluster assignment, we need to just add
            // ourselves to the cluster. Doing the addition here preserves
            // the topology and sort order from the original cluster.
            txentry.get().m_cluster->AddTransaction(txentry.get(), false);
        }
    }

    // After all assignments are made, either re-sort or re-chunk each cluster.
    std::vector<Cluster *> clusters_to_fix;
    {
        WITH_FRESH_EPOCH(m_epoch);
        for (auto it : txs) {
            if (!visited(it.get().m_cluster)) {
                clusters_to_fix.push_back(it.get().m_cluster);
            }
        }
    }
    for (auto cluster : clusters_to_fix) {
        if (sort) {
            cluster->Sort();
        } else {
            cluster->Rechunk();
        }
        cachedInnerUsage += cluster->GetMemoryUsage();
    }

    // Sanity check that all transactions are where they should be.
    for (auto it : txs) {
        assert(it.get().GetTx().GetHash() == it.get().m_loc.second->get().GetTx().GetHash());
    }
}

void CTxMemPool::removeForReorg(CChain& chain, std::function<bool(txiter)> check_final_and_mature)
{
    // Remove transactions spending a coinbase which are now immature and no-longer-final transactions
    AssertLockHeld(cs);
    AssertLockHeld(::cs_main);

    Entries txToRemove;
    for (indexed_transaction_set::const_iterator it = mapTx.begin(); it != mapTx.end(); it++) {
        if (check_final_and_mature(it)) txToRemove.push_back(it);
    }
    auto descendants = CalculateDescendants(txToRemove);

    setEntries setAllRemoves;
    setAllRemoves.insert(descendants.begin(), descendants.end());

    RemoveStaged(setAllRemoves, false, MemPoolRemovalReason::REORG);
    for (indexed_transaction_set::const_iterator it = mapTx.begin(); it != mapTx.end(); it++) {
        assert(TestLockPointValidity(chain, it->GetLockPoints()));
    }
}

void CTxMemPool::removeConflicts(const CTransaction &tx)
{
    // Remove transactions which depend on inputs of tx, recursively
    AssertLockHeld(cs);
    for (const CTxIn &txin : tx.vin) {
        auto it = mapNextTx.find(txin.prevout);
        if (it != mapNextTx.end()) {
            const CTransaction &txConflict = *it->second;
            if (txConflict != tx)
            {
                ClearPrioritisation(txConflict.GetHash());
                removeRecursive(txConflict, MemPoolRemovalReason::CONFLICT);
            }
        }
    }
}

/**
 * Called when a block is connected. Removes from mempool and updates the miner fee estimator.
 */
void CTxMemPool::removeForBlock(const std::vector<CTransactionRef>& vtx, unsigned int nBlockHeight)
{
    AssertLockHeld(cs);
    std::vector<const CTxMemPoolEntry*> entries;
    std::vector<txiter> entry_iters;
    for (const auto& tx : vtx)
    {
        uint256 hash = tx->GetHash();

        indexed_transaction_set::iterator i = mapTx.find(hash);
        if (i != mapTx.end()) {
            entries.push_back(&*i);
            entry_iters.push_back(i);
        }
    }
    // Before the txs in the new block have been removed from the mempool, update policy estimates
    if (minerPolicyEstimator) {minerPolicyEstimator->processBlock(nBlockHeight, entries);}
    static std::vector<Cluster *> cluster_clean_up;
    cluster_clean_up.clear();
    {
        WITH_FRESH_EPOCH(m_epoch);
        for (auto it : entry_iters)
        {
            bool delete_now{false};
            Cluster *cluster = it->m_cluster;
            if (!visited(cluster)) {
                if (cluster->m_tx_count > 1) {
                    cluster_clean_up.push_back(cluster);
                } else {
                    delete_now = true;
                }
                cachedInnerUsage -= cluster->GetMemoryUsage();
            }
            RemoveSingleTxForBlock(it);
            if (delete_now) {
                m_cluster_map.erase(cluster->m_id);
            }
        }
    }
    for (auto c : cluster_clean_up) {
        if (c->m_tx_count == 0) {
            m_cluster_map.erase(c->m_id);
        } else {
            RecalculateClusterAndMaybeSort(c, true);
        }
    }
    for (const auto& tx : vtx) {
        removeConflicts(*tx);
        ClearPrioritisation(tx->GetHash());
    }
    lastRollingFeeUpdate = GetTime();
    blockSinceLastRollingFeeBump = true;
}

void CTxMemPool::check(const CCoinsViewCache& active_coins_tip, int64_t spendheight) const
{
    if (m_check_ratio == 0) return;

    if (GetRand(m_check_ratio) >= 1) return;

    AssertLockHeld(::cs_main);
    LOCK(cs);
    LogPrint(BCLog::MEMPOOL, "Checking mempool with %u transactions and %u inputs\n", (unsigned int)mapTx.size(), (unsigned int)mapNextTx.size());

    uint64_t checkTotal = 0;
    CAmount check_total_fee{0};
    uint64_t innerUsage = 0;

    CCoinsViewCache mempoolDuplicate(const_cast<CCoinsViewCache*>(&active_coins_tip));

    for (const auto& it : GetSortedScoreWithTopology()) {
        checkTotal += it->GetTxSize();
        check_total_fee += it->GetFee();
        innerUsage += it->DynamicMemoryUsage();

        // Check that a transaction's location in cluster is correct.
        assert(it->GetTx().GetHash() == it->m_loc.second->get().GetTx().GetHash());
        const CTransaction& tx = it->GetTx();
        innerUsage += memusage::DynamicUsage(it->GetMemPoolParentsConst()) + memusage::DynamicUsage(it->GetMemPoolChildrenConst());
        CTxMemPoolEntry::Parents setParentCheck;
        for (const CTxIn &txin : tx.vin) {
            // Check that every mempool transaction's inputs refer to available coins, or other mempool tx's.
            indexed_transaction_set::const_iterator it2 = mapTx.find(txin.prevout.hash);
            if (it2 != mapTx.end()) {
                const CTransaction& tx2 = it2->GetTx();
                assert(tx2.vout.size() > txin.prevout.n && !tx2.vout[txin.prevout.n].IsNull());
                setParentCheck.insert(*it2);

                // Check that every parent is in the same cluster.
                assert(it2->m_cluster == it->m_cluster);
            }
            // We are iterating through the mempool entries sorted topologically and by score.
            // All parents must have been checked before their children and their coins added to
            // the mempoolDuplicate coins cache.
            assert(mempoolDuplicate.HaveCoin(txin.prevout));
            // Check whether its inputs are marked in mapNextTx.
            auto it3 = mapNextTx.find(txin.prevout);
            assert(it3 != mapNextTx.end());
            assert(it3->first == &txin.prevout);
            assert(it3->second == &tx);
        }
        auto comp = [](const CTxMemPoolEntry& a, const CTxMemPoolEntry& b) -> bool {
            return a.GetTx().GetHash() == b.GetTx().GetHash();
        };
        assert(setParentCheck.size() == it->GetMemPoolParentsConst().size());
        assert(std::equal(setParentCheck.begin(), setParentCheck.end(), it->GetMemPoolParentsConst().begin(), comp));

        // Check children against mapNextTx
        CTxMemPoolEntry::Children setChildrenCheck;
        auto iter = mapNextTx.lower_bound(COutPoint(it->GetTx().GetHash(), 0));
        for (; iter != mapNextTx.end() && iter->first->hash == it->GetTx().GetHash(); ++iter) {
            txiter childit = mapTx.find(iter->second->GetHash());
            assert(childit != mapTx.end()); // mapNextTx points to in-mempool transactions
            // Children should be in the same cluster.
            assert(childit->m_cluster == it->m_cluster);
            setChildrenCheck.insert(*childit);
        }
        assert(setChildrenCheck.size() == it->GetMemPoolChildrenConst().size());
        assert(std::equal(setChildrenCheck.begin(), setChildrenCheck.end(), it->GetMemPoolChildrenConst().begin(), comp));

        TxValidationState dummy_state; // Not used. CheckTxInputs() should always pass
        CAmount txfee = 0;
        assert(!tx.IsCoinBase());
        assert(Consensus::CheckTxInputs(tx, dummy_state, mempoolDuplicate, spendheight, txfee));
        for (const auto& input: tx.vin) mempoolDuplicate.SpendCoin(input.prevout);
        AddCoins(mempoolDuplicate, tx, std::numeric_limits<int>::max());
    }
    for (auto it = mapNextTx.cbegin(); it != mapNextTx.cend(); it++) {
        uint256 hash = it->second->GetHash();
        indexed_transaction_set::const_iterator it2 = mapTx.find(hash);
        const CTransaction& tx = it2->GetTx();
        assert(it2 != mapTx.end());
        assert(&tx == it->second);
    }

    // Check that clusters are sorted topologically and that the chunk metadata
    // matches the txs in the chunk.
    for (const auto & [id, cluster] : m_cluster_map) {
        assert(cluster->m_tx_count > 0); // no empty clusters
        CTxMemPoolEntry::Parents txs_so_far;
        for (size_t i=0; i<cluster->m_chunks.size(); ++i) {
            int64_t fee{0};
            int64_t size{0};
            assert(!cluster->m_chunks[i].txs.empty()); // no empty chunks
            for (auto it=cluster->m_chunks[i].txs.begin(); it != cluster->m_chunks[i].txs.end(); ++it) {
                fee += it->get().GetModifiedFee();
                size += it->get().GetTxSize();
                // Check that all parents are in txs_so_far
                for (const auto& parent : it->get().GetMemPoolParentsConst()) {
                    assert(txs_so_far.count(parent));
                }
                txs_so_far.insert(*it);
            }
            assert(fee == cluster->m_chunks[i].fee);
            assert(size == cluster->m_chunks[i].size);
        }
        innerUsage += cluster->GetMemoryUsage();
    }

    // Check that each cluster is connected.
    for (const auto & [id, cluster] : m_cluster_map) {
        // Since we've checked the parents and children already, we'll use
        // those values here.
        // We'll check that if we walk to every transaction reachable from the
        // first one, that we get every tx in the cluster.
        auto first_tx = cluster->m_chunks.front().txs.front();
        std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> work_queue;
        int reachable_txs = 1; // we'll count the transactions we reach.

        WITH_FRESH_EPOCH(m_epoch);
        visited(first_tx.get());
        assert(first_tx.get().GetMemPoolParentsConst().size() == 0); // first tx can never have parents.
        for (auto child : first_tx.get().GetMemPoolChildrenConst()) {
            work_queue.push_back(child);
            visited(child.get());
            ++reachable_txs;
        }
        while (work_queue.size() > 0) {
            auto next_tx = work_queue.back();
            work_queue.pop_back();
            for (auto parent : next_tx.get().GetMemPoolParentsConst()) {
                if (!visited(parent.get())) {
                    ++reachable_txs;
                    work_queue.push_back(parent);
                }
            }
            for (auto child : next_tx.get().GetMemPoolChildrenConst()) {
                if (!visited(child.get())) {
                    ++reachable_txs;
                    work_queue.push_back(child);
                }
            }
        }
        assert(reachable_txs == cluster->m_tx_count);
    }

    assert(totalTxSize == checkTotal);
    assert(m_total_fee == check_total_fee);
    assert(innerUsage == cachedInnerUsage);
}

// Return true if a comes before b in mempool sort order
bool CTxMemPool::CompareMiningScore(txiter a, txiter b) const
{
    if (a == b) return false; // An element cannot be less than itself.

    CAmount a_fee = a->m_cluster->m_chunks[a->m_loc.first].fee;
    int64_t a_size = a->m_cluster->m_chunks[a->m_loc.first].size;
    CAmount b_fee = b->m_cluster->m_chunks[b->m_loc.first].fee;
    int64_t b_size = b->m_cluster->m_chunks[b->m_loc.first].size;

    int64_t a_score = a_fee * b_size;
    int64_t b_score = b_fee * a_size;
    if (a_score != b_score) {
        return a_score > b_score;
    } else if (a->m_cluster != b->m_cluster) {
        // Equal scores in different clusters; sort by cluster id.
        return a->m_cluster->m_id < b->m_cluster->m_id;
        //return a->GetTx().GetHash() < b->GetTx().GetHash();
    } else if (a->m_loc.first != b->m_loc.first) {
        // Equal scores in same cluster; sort by chunk index.
        return a->m_loc.first < b->m_loc.first;
    } else {
        // Equal scores in same cluster and chunk; sort by position in chunk.
        for (auto it = a->m_cluster->m_chunks[a->m_loc.first].txs.begin();
                it != a->m_cluster->m_chunks[a->m_loc.first].txs.end(); ++it) {
            if (&(it->get()) == &(*a)) return true;
            if (&(it->get()) == &(*b)) return false;
        }
    }
    Assume(false); // this should not be reachable.
    return true;
}

void CTxMemPool::TopoSort(std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef>& to_be_sorted) const
{
    LOCK(cs);
    std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> sorted;
    sorted.reserve(to_be_sorted.size());
    std::vector<bool> already_added(to_be_sorted.size(), false);

    WITH_FRESH_EPOCH(m_epoch);
    for (size_t i=0; i<to_be_sorted.size(); ++i) {
        auto tx = to_be_sorted[i];
        // Check to see if this is already in the list.
        if (m_epoch.is_visited(tx.get().m_epoch_marker)) continue;

        // Gather the children for traversal.
        std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> work_queue;
        for (auto child : tx.get().GetMemPoolChildrenConst()) {
            if (!m_epoch.is_visited(child.get().m_epoch_marker)) {
                work_queue.push_back(child);

                while (!work_queue.empty()) {
                    auto next_entry = work_queue.back();
                    // Check to see if this entry is already added.
                    if (m_epoch.is_visited(next_entry.get().m_epoch_marker)) {
                        work_queue.pop_back();
                        continue;
                    }
                    // Otherwise, check to see if all children have been walked.
                    bool children_visited_already = true;
                    for (auto child : next_entry.get().GetMemPoolChildrenConst()) {
                        if (!m_epoch.is_visited(child.get().m_epoch_marker)) {
                            children_visited_already = false;
                            work_queue.push_back(child);
                        }
                    }
                    // If children have all been walked, we can remove this entry and
                    // add it to the list
                    if (children_visited_already) {
                        work_queue.pop_back();
                        sorted.push_back(next_entry);
                        visited(next_entry);
                    }
                }
            }
        }
        // Now that the descendants are added, we can add this entry.
        sorted.push_back(tx);
        visited(tx);
    }
    std::reverse(sorted.begin(), sorted.end());
    to_be_sorted.swap(sorted);
}

bool CTxMemPool::CompareMiningScoreWithTopology(const uint256& hasha, const uint256& hashb, bool wtxid)
{
    /* Return `true` if hasha should be considered sooner than hashb. Namely when:
     *   a is not in the mempool, but b is
     *   both are in the mempool and a has a higher mining score than b
     *   both are in the mempool and a appears before b in the same cluster
     */
    LOCK(cs);
    indexed_transaction_set::const_iterator j = wtxid ? get_iter_from_wtxid(hashb) : mapTx.find(hashb);
    if (j == mapTx.end()) return false;
    indexed_transaction_set::const_iterator i = wtxid ? get_iter_from_wtxid(hasha) : mapTx.find(hasha);
    if (i == mapTx.end()) return true;

    return CompareMiningScore(i, j);
}

std::vector<CTxMemPool::indexed_transaction_set::const_iterator> CTxMemPool::GetSortedScoreWithTopology() const
{
    std::vector<indexed_transaction_set::const_iterator> iters;
    AssertLockHeld(cs);

    iters.reserve(mapTx.size());

    for (indexed_transaction_set::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi) {
        iters.push_back(mi);
    }
    std::sort(iters.begin(), iters.end(), [this](const CTxMemPool::indexed_transaction_set::const_iterator& a, const CTxMemPool::indexed_transaction_set::const_iterator& b) {
        LOCK(this->cs); // TODO: this is unnecessary, to quiet a compiler warning
        return this->CompareMiningScore(a, b);
    });
    return iters;
}

void CTxMemPool::queryHashes(std::vector<uint256>& vtxid) const
{
    LOCK(cs);
    auto iters = GetSortedScoreWithTopology();

    vtxid.clear();
    vtxid.reserve(mapTx.size());

    for (auto it : iters) {
        vtxid.push_back(it->GetTx().GetHash());
    }
}

static TxMempoolInfo GetInfo(CTxMemPool::indexed_transaction_set::const_iterator it) {
    return TxMempoolInfo{it->GetSharedTx(), it->GetTime(), it->GetFee(), it->GetTxSize(), it->GetModifiedFee() - it->GetFee()};
}

std::vector<TxMempoolInfo> CTxMemPool::infoAll() const
{
    LOCK(cs);
    auto iters = GetSortedScoreWithTopology();

    std::vector<TxMempoolInfo> ret;
    ret.reserve(mapTx.size());
    for (auto it : iters) {
        ret.push_back(GetInfo(it));
    }

    return ret;
}

CTransactionRef CTxMemPool::get(const uint256& hash) const
{
    LOCK(cs);
    indexed_transaction_set::const_iterator i = mapTx.find(hash);
    if (i == mapTx.end())
        return nullptr;
    return i->GetSharedTx();
}

TxMempoolInfo CTxMemPool::info(const GenTxid& gtxid) const
{
    LOCK(cs);
    indexed_transaction_set::const_iterator i = (gtxid.IsWtxid() ? get_iter_from_wtxid(gtxid.GetHash()) : mapTx.find(gtxid.GetHash()));
    if (i == mapTx.end())
        return TxMempoolInfo();
    return GetInfo(i);
}

TxMempoolInfo CTxMemPool::info_for_relay(const GenTxid& gtxid, uint64_t last_sequence) const
{
    LOCK(cs);
    indexed_transaction_set::const_iterator i = (gtxid.IsWtxid() ? get_iter_from_wtxid(gtxid.GetHash()) : mapTx.find(gtxid.GetHash()));
    if (i != mapTx.end() && i->GetSequence() < last_sequence) {
        return GetInfo(i);
    } else {
        return TxMempoolInfo();
    }
}

void CTxMemPool::PrioritiseTransaction(const uint256& hash, const CAmount& nFeeDelta)
{
    {
        LOCK(cs);
        CAmount &delta = mapDeltas[hash];
        delta = SaturatingAdd(delta, nFeeDelta);
        txiter it = mapTx.find(hash);
        if (it != mapTx.end()) {
            mapTx.modify(it, [&nFeeDelta](CTxMemPoolEntry& e) { e.UpdateModifiedFee(nFeeDelta); });

            ++nTransactionsUpdated;

            cachedInnerUsage -= it->m_cluster->GetMemoryUsage();

            // Re-sort the cluster this came from.
            it->m_cluster->Sort();

            cachedInnerUsage += it->m_cluster->GetMemoryUsage();
        }
        if (delta == 0) {
            mapDeltas.erase(hash);
            LogPrintf("PrioritiseTransaction: %s (%sin mempool) delta cleared\n", hash.ToString(), it == mapTx.end() ? "not " : "");
        } else {
            LogPrintf("PrioritiseTransaction: %s (%sin mempool) fee += %s, new delta=%s\n",
                      hash.ToString(),
                      it == mapTx.end() ? "not " : "",
                      FormatMoney(nFeeDelta),
                      FormatMoney(delta));
        }
    }
}

void CTxMemPool::ApplyDelta(const uint256& hash, CAmount &nFeeDelta) const
{
    AssertLockHeld(cs);
    std::map<uint256, CAmount>::const_iterator pos = mapDeltas.find(hash);
    if (pos == mapDeltas.end())
        return;
    const CAmount &delta = pos->second;
    nFeeDelta += delta;
}

void CTxMemPool::ClearPrioritisation(const uint256& hash)
{
    AssertLockHeld(cs);
    mapDeltas.erase(hash);
}

std::vector<CTxMemPool::delta_info> CTxMemPool::GetPrioritisedTransactions() const
{
    AssertLockNotHeld(cs);
    LOCK(cs);
    std::vector<delta_info> result;
    result.reserve(mapDeltas.size());
    for (const auto& [txid, delta] : mapDeltas) {
        const auto iter{mapTx.find(txid)};
        const bool in_mempool{iter != mapTx.end()};
        std::optional<CAmount> modified_fee;
        if (in_mempool) modified_fee = iter->GetModifiedFee();
        result.emplace_back(delta_info{in_mempool, delta, modified_fee, txid});
    }
    return result;
}

const CTransaction* CTxMemPool::GetConflictTx(const COutPoint& prevout) const
{
    const auto it = mapNextTx.find(prevout);
    return it == mapNextTx.end() ? nullptr : it->second;
}

std::optional<CTxMemPool::txiter> CTxMemPool::GetIter(const uint256& txid) const
{
    auto it = mapTx.find(txid);
    if (it != mapTx.end()) return it;
    return std::nullopt;
}

CTxMemPool::setEntries CTxMemPool::GetIterSet(const std::set<uint256>& hashes) const
{
    CTxMemPool::setEntries ret;
    for (const auto& h : hashes) {
        const auto mi = GetIter(h);
        if (mi) ret.insert(*mi);
    }
    return ret;
}

std::vector<CTxMemPool::txiter> CTxMemPool::GetIterVec(const std::vector<uint256>& txids) const
{
    AssertLockHeld(cs);
    std::vector<txiter> ret;
    ret.reserve(txids.size());
    for (const auto& txid : txids) {
        const auto it{GetIter(txid)};
        if (!it) return {};
        ret.push_back(*it);
    }
    return ret;
}

bool CTxMemPool::HasNoInputsOf(const CTransaction &tx) const
{
    for (unsigned int i = 0; i < tx.vin.size(); i++)
        if (exists(GenTxid::Txid(tx.vin[i].prevout.hash)))
            return false;
    return true;
}

CCoinsViewMemPool::CCoinsViewMemPool(CCoinsView* baseIn, const CTxMemPool& mempoolIn) : CCoinsViewBacked(baseIn), mempool(mempoolIn) { }

bool CCoinsViewMemPool::GetCoin(const COutPoint &outpoint, Coin &coin) const {
    // Check to see if the inputs are made available by another tx in the package.
    // These Coins would not be available in the underlying CoinsView.
    if (auto it = m_temp_added.find(outpoint); it != m_temp_added.end()) {
        coin = it->second;
        return true;
    }

    // If an entry in the mempool exists, always return that one, as it's guaranteed to never
    // conflict with the underlying cache, and it cannot have pruned entries (as it contains full)
    // transactions. First checking the underlying cache risks returning a pruned entry instead.
    CTransactionRef ptx = mempool.get(outpoint.hash);
    if (ptx) {
        if (outpoint.n < ptx->vout.size()) {
            coin = Coin(ptx->vout[outpoint.n], MEMPOOL_HEIGHT, false);
            m_non_base_coins.emplace(outpoint);
            return true;
        } else {
            return false;
        }
    }
    return base->GetCoin(outpoint, coin);
}

void CCoinsViewMemPool::PackageAddTransaction(const CTransactionRef& tx)
{
    for (unsigned int n = 0; n < tx->vout.size(); ++n) {
        m_temp_added.emplace(COutPoint(tx->GetHash(), n), Coin(tx->vout[n], MEMPOOL_HEIGHT, false));
        m_non_base_coins.emplace(tx->GetHash(), n);
    }
}
void CCoinsViewMemPool::Reset()
{
    m_temp_added.clear();
    m_non_base_coins.clear();
}

size_t CTxMemPool::DynamicMemoryUsage() const {
    LOCK(cs);
    // Estimate the overhead of mapTx to be 9 pointers + an allocation, as no exact formula for boost::multi_index_contained is implemented.
    return memusage::MallocUsage(sizeof(CTxMemPoolEntry) + 9 * sizeof(void*)) * mapTx.size() + memusage::DynamicUsage(mapNextTx) + memusage::DynamicUsage(mapDeltas) + memusage::DynamicUsage(vTxHashes) + memusage::DynamicUsage(m_cluster_map) + cachedInnerUsage;
}

void CTxMemPool::RemoveUnbroadcastTx(const uint256& txid, const bool unchecked) {
    LOCK(cs);

    if (m_unbroadcast_txids.erase(txid))
    {
        LogPrint(BCLog::MEMPOOL, "Removed %i from set of unbroadcast txns%s\n", txid.GetHex(), (unchecked ? " before confirmation that txn was sent out" : ""));
    }
}

void CTxMemPool::RemoveChunkForEviction(Cluster *cluster, std::list<CTxMemPoolEntry::CTxMemPoolEntryRef>& entries)
{
    AssertLockHeld(cs);

    cachedInnerUsage -= cluster->GetMemoryUsage();

    setEntries entriesToRemove;
    for (auto entry_ref : entries) {
        entriesToRemove.insert(mapTx.iterator_to(entry_ref.get()));
    }
    UpdateForRemoveFromMempool(entriesToRemove);
    for (auto it : entriesToRemove) {
        removeUnchecked(it, MemPoolRemovalReason::SIZELIMIT);
    }

    cachedInnerUsage += cluster->GetMemoryUsage();
    // Note: at this point the clusters will still be sorted, but they may need
    // to be split.
}

void CTxMemPool::RemoveSingleTxForBlock(txiter it)
{
    UpdateParentsOf(false, it);
    UpdateChildrenForRemoval(it);

    removeUnchecked(it, MemPoolRemovalReason::BLOCK);
}

void CTxMemPool::RemoveStaged(setEntries &stage, bool updateDescendants, MemPoolRemovalReason reason) {
    AssertLockHeld(cs);
    UpdateForRemoveFromMempool(stage);

    std::vector<Cluster *> clusters;
    {
        WITH_FRESH_EPOCH(m_epoch);
        for (txiter it : stage) {
            if (!visited(it->m_cluster)) {
                cachedInnerUsage -= it->m_cluster->GetMemoryUsage();
                clusters.push_back(it->m_cluster);
            }
            removeUnchecked(it, reason);
        }
    }

    // Cluster removals need to be cleaned up.
    for (Cluster *cluster : clusters) {
        if (cluster->m_tx_count == 0) {
            m_cluster_map.erase(cluster->m_id);
        } else {
            // Potentially split clusters and re-sort.
            // TODO: we can avoid re-sorting in the case of eviction.
            RecalculateClusterAndMaybeSort(cluster, true);
        }
    }
}

int CTxMemPool::Expire(std::chrono::seconds time)
{
    AssertLockHeld(cs);
    indexed_transaction_set::index<entry_time>::type::iterator it = mapTx.get<entry_time>().begin();
    Entries toremove;
    while (it != mapTx.get<entry_time>().end() && it->GetTime() < time) {
        toremove.push_back(mapTx.project<0>(it));
        it++;
    }
    auto descendants = CalculateDescendants(toremove);

    setEntries stage;
    stage.insert(descendants.begin(), descendants.end());

    RemoveStaged(stage, false, MemPoolRemovalReason::EXPIRY);
    return stage.size();
}

void CTxMemPool::UpdateChild(txiter entry, txiter child, bool add)
{
    AssertLockHeld(cs);
    CTxMemPoolEntry::Children s;
    if (add && entry->GetMemPoolChildren().insert(*child).second) {
        cachedInnerUsage += memusage::IncrementalDynamicUsage(s);
    } else if (!add && entry->GetMemPoolChildren().erase(*child)) {
        cachedInnerUsage -= memusage::IncrementalDynamicUsage(s);
    }
}

void CTxMemPool::UpdateParent(txiter entry, txiter parent, bool add)
{
    AssertLockHeld(cs);
    CTxMemPoolEntry::Parents s;
    if (add && entry->GetMemPoolParents().insert(*parent).second) {
        cachedInnerUsage += memusage::IncrementalDynamicUsage(s);
    } else if (!add && entry->GetMemPoolParents().erase(*parent)) {
        cachedInnerUsage -= memusage::IncrementalDynamicUsage(s);
    }
}

CFeeRate CTxMemPool::GetMinFee(size_t sizelimit) const {
    LOCK(cs);
    if (!blockSinceLastRollingFeeBump || rollingMinimumFeeRate == 0)
        return CFeeRate(llround(rollingMinimumFeeRate));

    int64_t time = GetTime();
    if (time > lastRollingFeeUpdate + 10) {
        double halflife = ROLLING_FEE_HALFLIFE;
        if (DynamicMemoryUsage() < sizelimit / 4)
            halflife /= 4;
        else if (DynamicMemoryUsage() < sizelimit / 2)
            halflife /= 2;

        rollingMinimumFeeRate = rollingMinimumFeeRate / pow(2.0, (time - lastRollingFeeUpdate) / halflife);
        lastRollingFeeUpdate = time;

        if (rollingMinimumFeeRate < (double)m_incremental_relay_feerate.GetFeePerK() / 2) {
            rollingMinimumFeeRate = 0;
            return CFeeRate(0);
        }
    }
    return std::max(CFeeRate(llround(rollingMinimumFeeRate)), m_incremental_relay_feerate);
}

void CTxMemPool::trackPackageRemoved(const CFeeRate& rate) {
    AssertLockHeld(cs);
    if (rate.GetFeePerK() > rollingMinimumFeeRate) {
        rollingMinimumFeeRate = rate.GetFeePerK();
        blockSinceLastRollingFeeBump = false;
    }
}

void CTxMemPool::TrimToSize(size_t sizelimit, std::vector<COutPoint>* pvNoSpendsRemaining) {
    AssertLockHeld(cs);

    unsigned nTxnRemoved = 0;
    CFeeRate maxFeeRateRemoved(0);

    // Use a heap to determine which chunks to evict, but only make the heap if
    // we're actually above the size limit.
    std::vector<Cluster::HeapEntry> heap_chunks;
    std::set<Cluster*> clusters_with_evictions;
    while (!mapTx.empty() && DynamicMemoryUsage() > sizelimit) {
        if (heap_chunks.empty()) {
            for (const auto & [id, cluster] : m_cluster_map) {
                if (!cluster->m_chunks.empty()) {
                    heap_chunks.emplace_back(cluster->m_chunks.end()-1, cluster.get());
                }
            }
        }

        // Define comparison operator on our heap entries (using feerate of chunks).
        auto cmp = [](const Cluster::HeapEntry& a, const Cluster::HeapEntry& b) {
            // TODO: branch on size of fee to do this as 32-bit calculation
            // instead? etc
            return a.first->fee*b.first->size > b.first->fee*a.first->size;
        };

        std::make_heap(heap_chunks.begin(), heap_chunks.end(), cmp);

        // Remove the top element (lowest feerate) and evict.
        auto worst_chunk = heap_chunks.front();

        assert(worst_chunk.first->size > 0);

        std::pop_heap(heap_chunks.begin(), heap_chunks.end(), cmp);
        heap_chunks.pop_back();
        if (worst_chunk.first != worst_chunk.second->m_chunks.begin()) {
            // If we're not at the beginning of the cluster's chunk list, we can
            // just decrement the iterator to get the next-lowest feerate chunk.
            heap_chunks.emplace_back(worst_chunk.first-1, worst_chunk.second);
            std::push_heap(heap_chunks.begin(), heap_chunks.end(), cmp);
        }

        clusters_with_evictions.insert(worst_chunk.second);

        // We set the new mempool min fee to the feerate of the removed set, plus the
        // "minimum reasonable fee rate" (ie some value under which we consider txn
        // to have 0 fee). This way, we don't allow txn to enter mempool with feerate
        // equal to txn which were removed with no block in between.
        CFeeRate removed(worst_chunk.first->fee, worst_chunk.first->size);
        removed += m_incremental_relay_feerate;
        trackPackageRemoved(removed);
        maxFeeRateRemoved = std::max(maxFeeRateRemoved, removed);

        nTxnRemoved += worst_chunk.first->txs.size();

        std::vector<CTransaction> txn;
        if (pvNoSpendsRemaining) {
            txn.reserve(worst_chunk.first->txs.size());
            for (auto tx_entry_ref : worst_chunk.first->txs)
                txn.push_back(tx_entry_ref.get().GetTx());
        }

        // We'll remove this chunk without otherwise updating the cluster (ie
        // without trying to re-sort, and without trying to re-partition/split
        // the cluster if it's no longer connected).
        RemoveChunkForEviction(worst_chunk.second, worst_chunk.first->txs);
        if (pvNoSpendsRemaining) {
            for (const CTransaction& tx : txn) {
                for (const CTxIn& txin : tx.vin) {
                    if (exists(GenTxid::Txid(txin.prevout.hash))) continue;
                    pvNoSpendsRemaining->push_back(txin.prevout);
                }
            }
        }
    }

    // Before we can return, we have to clean up the clusters that saw
    // evictions, because they will have stray chunks and may need to be
    // re-partitioned.
    // However, these clusters do not need to be re-sorted, because evicted
    // chunks at the end can never change the relative ordering of transactions
    // that come before them.
    for (Cluster* cluster : clusters_with_evictions) {
        cachedInnerUsage -= cluster->GetMemoryUsage();
        if (cluster->m_tx_count == 0) {
            m_cluster_map.erase(cluster->m_id);
        } else {
            RecalculateClusterAndMaybeSort(cluster, false);
        }
    }

    if (maxFeeRateRemoved > CFeeRate(0)) {
        LogPrint(BCLog::MEMPOOL, "Removed %u txn, rolling minimum fee bumped to %s\n", nTxnRemoved, maxFeeRateRemoved.ToString());
    }
}

void CTxMemPool::CalculateAncestorData(const CTxMemPoolEntry& entry, size_t& ancestor_count, size_t& ancestor_size, CAmount& ancestor_fees) const
{
    ancestor_count = 1;
    ancestor_size = entry.GetTxSize();
    ancestor_fees = entry.GetModifiedFee();
    std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> work_queue;

    WITH_FRESH_EPOCH(m_epoch);
    for (auto tx : entry.GetMemPoolParentsConst()) {
        work_queue.push_back(tx);
        visited(tx);
    }
    while (!work_queue.empty()) {
        auto next_entry = work_queue.back();
        work_queue.pop_back();
        ancestor_size += next_entry.get().GetTxSize();
        ++ancestor_count;
        ancestor_fees += next_entry.get().GetModifiedFee();
        for (auto tx : next_entry.get().GetMemPoolParentsConst()) {
            if (!visited(tx)) work_queue.push_back(tx);
        }
    }
}

void CTxMemPool::CalculateDescendantData(const CTxMemPoolEntry& entry, size_t& descendant_count, size_t& descendant_size, CAmount& descendant_fees) const
{
    descendant_count = 1;
    descendant_size = entry.GetTxSize();
    descendant_fees = entry.GetModifiedFee();
    std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> work_queue;

    WITH_FRESH_EPOCH(m_epoch);
    for (auto tx : entry.GetMemPoolChildrenConst()) {
        work_queue.push_back(tx);
        visited(tx);
    }
    while (!work_queue.empty()) {
        auto next_entry = work_queue.back();
        work_queue.pop_back();
        descendant_size += next_entry.get().GetTxSize();
        ++descendant_count;
        descendant_fees += next_entry.get().GetModifiedFee();
        for (auto tx : next_entry.get().GetMemPoolChildrenConst()) {
            if (!visited(tx)) work_queue.push_back(tx);
        }
    }
}

void CTxMemPool::GetTransactionAncestry(const uint256& txid, size_t& ancestors, size_t& clustersize, size_t* const ancestorsize, CAmount* const ancestorfees) const {
    LOCK(cs);
    auto it = mapTx.find(txid);
    ancestors = clustersize = 0;
    if (it != mapTx.end()) {
        size_t dummysize{0};
        CAmount dummyfees{0};
        CalculateAncestorData(*it, ancestors, ancestorsize ? *ancestorsize :
                dummysize, ancestorfees ? *ancestorfees : dummyfees);
        clustersize = it->m_cluster->m_tx_count;
    }
}

bool CTxMemPool::GetLoadTried() const
{
    LOCK(cs);
    return m_load_tried;
}

void CTxMemPool::SetLoadTried(bool load_tried)
{
    LOCK(cs);
    m_load_tried = load_tried;
}

std::vector<CTxMemPool::txiter> CTxMemPool::GatherClusters(const std::vector<uint256>& txids) const
{
    AssertLockHeld(cs);
    std::vector<txiter> clustered_txs{GetIterVec(txids)};
    // Use epoch: visiting an entry means we have added it to the clustered_txs vector. It does not
    // necessarily mean the entry has been processed.
    WITH_FRESH_EPOCH(m_epoch);
    for (const auto& it : clustered_txs) {
        visited(it);
    }
    // i = index of where the list of entries to process starts
    for (size_t i{0}; i < clustered_txs.size(); ++i) {
        // DoS protection: if there are 500 or more entries to process, just quit.
        if (clustered_txs.size() > 500) return {};
        const txiter& tx_iter = clustered_txs.at(i);
        for (const auto& entries : {tx_iter->GetMemPoolParentsConst(), tx_iter->GetMemPoolChildrenConst()}) {
            for (const CTxMemPoolEntry& entry : entries) {
                const auto entry_it = mapTx.iterator_to(entry);
                if (!visited(entry_it)) {
                    clustered_txs.push_back(entry_it);
                }
            }
        }
    }
    return clustered_txs;
}

CTxMemPoolEntry::CTxMemPoolEntryRef Cluster::GetLastTransaction()
{
    assert(m_tx_count > 0);
    for (auto chunkit = m_chunks.rbegin(); chunkit != m_chunks.rend(); ++chunkit) {
        if (!chunkit->txs.empty()) return chunkit->txs.back();
    }
    // Unreachable
    assert(false);
}

void Cluster::AddTransaction(const CTxMemPoolEntry& entry, bool sort)
{
    m_chunks.emplace_back(entry.GetModifiedFee(), entry.GetTxSize());
    m_chunks.back().txs.emplace_back(entry);
    entry.m_cluster = this;
    ++m_tx_count;
    m_tx_size += entry.GetTxSize();
    if (sort) Sort();
    return;
}

void Cluster::RemoveTransaction(const CTxMemPoolEntry& entry)
{
    m_chunks[entry.m_loc.first].txs.erase(entry.m_loc.second);

    // Chunk (or cluster) may now be empty, but this will get cleaned up
    // when the cluster is re-sorted (or when the cluster is deleted) Note:
    // if we cleaned up empty chunks here, then this would break the
    // locations of other entries in the cluster. Since we would like to be
    // able to do multiple removals in a row and then clean up the sort, we
    // can't clean up empty chunks here.
    --m_tx_count;
    m_tx_size -= entry.GetTxSize();
    return;
}

void Cluster::RechunkFromLinearization(std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef>& txs, bool reassign_locations)
{
    m_chunks.clear();
    m_tx_size = 0;

    for (auto txentry : txs) {
        m_chunks.emplace_back(txentry.get().GetModifiedFee(), txentry.get().GetTxSize());
        m_chunks.back().txs.emplace_back(txentry);
        while (m_chunks.size() >= 2) {
            auto cur_iter = std::prev(m_chunks.end());
            auto prev_iter = std::prev(cur_iter);
            double feerate_prev = prev_iter->fee*cur_iter->size;
            double feerate_cur = cur_iter->fee*prev_iter->size;
            // We only combine chunks if the feerate would go up; if two
            // chunks have equal feerate, we prefer to keep the smaller
            // chunksize (which is generally better for both mining and
            // eviction).
            if (feerate_cur > feerate_prev) {
                prev_iter->fee += cur_iter->fee;
                prev_iter->size += cur_iter->size;
                prev_iter->txs.splice(prev_iter->txs.end(), cur_iter->txs, cur_iter->txs.begin(), cur_iter->txs.end());
                m_chunks.erase(cur_iter);
            } else {
                break;
            }
        }
        m_tx_size += txentry.get().GetTxSize();
    }

    if (reassign_locations) {
        // Update locations of all transactions
        for (size_t i=0; i<m_chunks.size(); ++i) {
            for (auto it = m_chunks[i].txs.begin(); it != m_chunks[i].txs.end(); ++it) {
                it->get().m_loc = {i, it};
            }
        }
    }
}

namespace {

template <typename SetType>
std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> InvokeSort(size_t tx_count, const std::vector<Cluster::Chunk>& chunks)
{
    std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> txs;
    cluster_linearize::Cluster<SetType> cluster;
    const auto time_1{SteadyClock::now()};

    std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> orig_txs;
    std::vector<std::pair<const CTxMemPoolEntry*, unsigned>> entry_to_index;
    cluster_linearize::LinearizationResult result;

    cluster.reserve(tx_count);
    entry_to_index.reserve(tx_count);
    cluster.clear();
    for (auto &chunk : chunks) {
        for (auto tx : chunk.txs) {
            orig_txs.emplace_back(tx);
            cluster.emplace_back(FeeFrac(uint64_t(tx.get().GetModifiedFee()+1000000*uint64_t(tx.get().GetTxSize())), tx.get().GetTxSize()), SetType{});
            entry_to_index.emplace_back(&(tx.get()), cluster.size() - 1);
        }
    }
    std::sort(entry_to_index.begin(), entry_to_index.end());
    for (size_t i=0; i<orig_txs.size(); ++i) {
        for (auto& parent : orig_txs[i].get().GetMemPoolParentsConst()) {
            auto it = std::lower_bound(entry_to_index.begin(), entry_to_index.end(), &(parent.get()),
                    [&](const auto& a, const auto& b) { return std::less<const CTxMemPoolEntry*>()(a.first, b); });
            assert(it != entry_to_index.end());
            assert(it->first == &(parent.get()));
            cluster[i].second.Set(it->second);
        }
    }
    result = cluster_linearize::LinearizeCluster(cluster, 0, 0);
    txs.clear();
    for (auto index : result.linearization) {
        txs.push_back(orig_txs[index]);
    }

    const auto time_2{SteadyClock::now()};
    if (tx_count >= 10) {
        double time_millis = Ticks<MillisecondsDouble>(time_2-time_1);

        LogPrint(BCLog::BENCH, "InvokeSort linearize cluster: %zu txs, %.4fms, %u iter, %.1fns/iter, %u comps, %.1fns/comp, encoding: %s\n",
                tx_count,
                time_millis,
                result.iterations,
                time_millis * 1000000.0 / (result.iterations > 0 ? result.iterations : result.iterations+1),
                result.comparisons,
                time_millis * 1000000.0 / (result.comparisons > 0 ? result.comparisons : result.comparisons+1),
                HexStr(cluster_linearize::DumpCluster(cluster)));
    }
    return txs;
}

} // namespace

void Cluster::Sort(bool reassign_locations)
{
    std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> txs;
    if (m_tx_count <= 32) {
        txs = InvokeSort<BitSet<32>>(m_tx_count, m_chunks);
    } else if (m_tx_count <= 64) {
        txs = InvokeSort<BitSet<64>>(m_tx_count, m_chunks);
    } else if (m_tx_count <= 128) {
        txs = InvokeSort<BitSet<128>>(m_tx_count, m_chunks);
    } else if (m_tx_count <= 192) {
        txs = InvokeSort<BitSet<192>>(m_tx_count, m_chunks);
    } else if (m_tx_count <= 256) {
        txs = InvokeSort<BitSet<256>>(m_tx_count, m_chunks);
    } else if (m_tx_count <= 320) {
        txs = InvokeSort<BitSet<320>>(m_tx_count, m_chunks);
    } else if (m_tx_count <= 384) {
        txs = InvokeSort<BitSet<384>>(m_tx_count, m_chunks);
    } else if (m_tx_count <= 1280) {
        txs = InvokeSort<BitSet<1280>>(m_tx_count, m_chunks);
    } else {
        // Only do the topological sort for big clusters
        for (auto &chunk : m_chunks) {
            for (auto chunk_tx : chunk.txs) {
                txs.emplace_back(chunk_tx.get());
            }
        }
        m_mempool->TopoSort(txs);
    }
    RechunkFromLinearization(txs, reassign_locations);
}

void Cluster::Rechunk()
{
    std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> txs;

    // Insert all transactions from the cluster into txs
    for (auto &chunk : m_chunks) {
        for (auto chunk_tx : chunk.txs) {
            txs.push_back(chunk_tx);
        }
    }

    RechunkFromLinearization(txs, true);
}

// Merge the clusters from [first, last) into this cluster.
void Cluster::Merge(std::vector<Cluster*>::iterator first, std::vector<Cluster*>::iterator last, bool this_cluster_first)
{
    // Check to see if we have anything to do.
    if (first == last) return;

    std::vector<Chunk> new_chunks;
    std::vector<Cluster::HeapEntry> heap_chunks;

    int64_t total_txs = m_tx_count;

    // Make a heap of all the best chunks.
    for (auto it = first; it != last; ++it) {
        if ((*it)->m_chunks.size() > 0) {
            heap_chunks.emplace_back((*it)->m_chunks.begin(), *it);
        }
        total_txs += (*it)->m_tx_count;
    }

    // During a reorg, we want to merge clusters corresponding to descendants
    // so that they appear after the cluster with their parent. This allows us
    // to trim megaclusters down to our cluster size limit in a way that
    // respects topology but still preferences higher feerate chunks over lower
    // feerate chunks.
    if (this_cluster_first) {
        new_chunks = std::move(m_chunks);
        m_chunks.clear();
    } else {
        heap_chunks.emplace_back(m_chunks.begin(), this);
    }
    // Define comparison operator on our heap entries (using feerate of chunks).
    auto cmp = [](const Cluster::HeapEntry& a, const Cluster::HeapEntry& b) {
        // TODO: branch on size of fee to do this as 32-bit calculation
        // instead? etc
        return a.first->fee*b.first->size < b.first->fee*a.first->size;
    };

    std::make_heap(heap_chunks.begin(), heap_chunks.end(), cmp);

    while (!heap_chunks.empty()) {
        // Take the best chunk from the heap.
        auto best_chunk = heap_chunks.front();
        new_chunks.emplace_back(std::move(*(best_chunk.first)));
        // Remove the best chunk from the heap.
        std::pop_heap(heap_chunks.begin(), heap_chunks.end(), cmp);
        heap_chunks.pop_back();
        // If the cluster has more chunks, add the next best chunk to the heap.
        ++best_chunk.first;
        if (best_chunk.first != best_chunk.second->m_chunks.end()) {
            heap_chunks.emplace_back(best_chunk.first, best_chunk.second);
            std::push_heap(heap_chunks.begin(), heap_chunks.end(), cmp);
        }
    }

    // At this point we've merged the clusters into new_chunks.
    m_chunks = std::move(new_chunks);

    m_tx_count=0;

    // Update the cluster and location information for each transaction.
    for (size_t i=0; i<m_chunks.size(); ++i) {
        for (auto it = m_chunks[i].txs.begin(); it != m_chunks[i].txs.end(); ++it) {
            it->get().m_cluster = this;
            it->get().m_loc = {i, it};
            ++m_tx_count;
        }
    }

    assert(m_tx_count == total_txs);
}

// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/quantum.h>

#include <chain.h>
#include <consensus/merkle.h>
#include <hash.h>
#include <kernel/chainstatemanager_opts.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/script.h>
#include <streams.h>
#include <sync.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/strencodings.h>
#include <util/syserror.h>
#include <validation.h>

#include <exception>
#include <optional>
#include <span>
#include <utility>
#include <vector>

using namespace util::hex_literals;

namespace node {

namespace {
//! A NUMS point with a *known* discrete log (sha256("bitcoin-quantum fake NUMS
//! point")*G), used only under -test=fakenums so that a theft -- and therefore a
//! verifying proof -- can be simulated. The matching scalar lives in
//! test/functional/test_framework/quantum.py (FAKE_NUMS_SECKEY).
constexpr XOnlyPubKey FAKE_NUMS_POINT{
    []() consteval { return XOnlyPubKey{"5f0fb4b5d2ecfd58722a44cc59da0f9e22875ef90164f8ba6af3a61db1951177"_hex_u8}; }(),
};
} // namespace

std::optional<std::vector<unsigned char>> ProofFromScript(std::span<const unsigned char> script)
{
    // Expect exactly: OP_RETURN <QUANTUM_PROOF_SIZE-byte push>.
    const CScript spk(script.begin(), script.end());
    CScript::const_iterator pc{spk.begin()};
    opcodetype op;
    if (!spk.GetOp(pc, op) || op != OP_RETURN) return std::nullopt;
    std::vector<unsigned char> data;
    if (!spk.GetOp(pc, op, data)) return std::nullopt;
    if (pc != spk.end()) return std::nullopt; // more than one push
    if (data.size() != QUANTUM_PROOF_SIZE) return std::nullopt;
    return data;
}

void QuantumProofStore::SetNumsPoint(const XOnlyPubKey& nums)
{
    LOCK(m_mutex);
    m_nums = nums;
}

void QuantumProofStore::UseFakeNumsPoint()
{
    LOCK(m_mutex);
    m_nums = FAKE_NUMS_POINT;
}

XOnlyPubKey QuantumProofStore::GetNumsPoint() const
{
    LOCK(m_mutex);
    return m_nums;
}

bool QuantumProofStore::VerifyLocked(std::span<const unsigned char> proof) const
{
    if (proof.size() != QUANTUM_PROOF_SIZE) return false;
    // Split a || R || s || m.
    const uint256 tweak{proof.subspan(0, 32)};
    const std::span<const unsigned char> sig{proof.subspan(32, 64)};
    const uint256 msg{proof.subspan(96, 32)};
    // P = N + a*G
    const auto tweaked{m_nums.AddTweak(tweak)};
    if (!tweaked) return false;
    return tweaked->first.VerifySchnorr(msg, sig);
}

bool QuantumProofStore::Verify(std::span<const unsigned char> proof) const
{
    LOCK(m_mutex);
    return VerifyLocked(proof);
}

bool QuantumProofStore::Add(std::vector<unsigned char> proof)
{
    if (proof.size() != QUANTUM_PROOF_SIZE) return false;
    LOCK(m_mutex);
    if (m_active_since.has_value()) return false; // tripwire already fired
    if (m_proof.has_value()) return false;        // we already hold a proof
    if (!VerifyLocked(proof)) return false;
    m_proof = std::move(proof);
    return true;
}

std::optional<std::vector<unsigned char>> QuantumProofStore::GetProof() const
{
    LOCK(m_mutex);
    return m_proof;
}

std::optional<int> QuantumProofStore::ActivationHeight() const
{
    LOCK(m_mutex);
    return m_active_since;
}

bool QuantumProofStore::IsActiveAtHeight(int height) const
{
    LOCK(m_mutex);
    return m_active_since.has_value() && height >= *m_active_since;
}

void QuantumProofStore::BlockConnected(const kernel::ChainstateRole& role, const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex)
{
    if (pindex == nullptr || block->vtx.empty()) return;
    LOCK(m_mutex);
    if (m_active_since.has_value()) return; // already activated; stop scanning
    // Scan the coinbase outputs for a published, valid proof.
    for (const CTxOut& out : block->vtx[0]->vout) {
        const auto proof{ProofFromScript(std::span<const unsigned char>(out.scriptPubKey.data(), out.scriptPubKey.size()))};
        if (!proof || !VerifyLocked(*proof)) continue;
        if (!m_proof.has_value()) m_proof = *proof;
        // Instant activation: the tripwire is active from the next block.
        m_active_since = pindex->nHeight + 1;
        m_activation_block = pindex->GetBlockHash();
        // Persist the coinbase and its merkle path so activation can be restored
        // and re-verified after a restart without reading the block body.
        WriteActivationFile(*block->vtx[0], TransactionMerklePath(*block, 0));
        LogInfo("Quantum tripwire activated by block %d (%s); active from height %d\n",
                pindex->nHeight, pindex->GetBlockHash().ToString(), *m_active_since);
        break;
    }
}

void QuantumProofStore::BlockDisconnected(const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex)
{
    if (pindex == nullptr) return;
    LOCK(m_mutex);
    if (m_active_since.has_value() && pindex->GetBlockHash() == m_activation_block) {
        // The activating block was rolled back; resume scanning. Keep m_proof so
        // it is re-published on the new chain. Deactivation is keyed on the
        // activation block alone, so a *later* block that also carried a proof
        // being reorged out does not deactivate the tripwire.
        m_active_since.reset();
        m_activation_block.SetNull();
        RemoveActivationFile();
    }
}

void QuantumProofStore::SetActivationFilePath(fs::path path)
{
    LOCK(m_mutex);
    m_activation_file = std::move(path);
}

void QuantumProofStore::WriteActivationFile(const CTransaction& coinbase, const std::vector<uint256>& merkle_path) const
{
    if (m_activation_file.empty() || m_activation_block.IsNull()) return;
    try {
        AutoFile file{fsbridge::fopen(m_activation_file, "wb")};
        if (file.IsNull()) {
            LogWarning("Cannot open quantum activation file %s for writing\n", fs::PathToString(m_activation_file));
            return;
        }
        // The witness (just the BIP141 reserved value) is irrelevant to both the
        // txid used in the merkle path and the proof, so it is omitted.
        file << m_activation_block << TX_NO_WITNESS(coinbase) << merkle_path;
        // AutoFile requires written files to be closed explicitly so close errors
        // can be surfaced; its destructor asserts the file was already closed.
        if (file.fclose() != 0) {
            const int errno_save{errno};
            LogWarning("Failed to close quantum activation file %s: %s\n", fs::PathToString(m_activation_file), SysErrorString(errno_save));
        }
    } catch (const std::exception& e) {
        LogWarning("Failed to write quantum activation file: %s\n", e.what());
    }
}

void QuantumProofStore::RemoveActivationFile() const
{
    if (m_activation_file.empty()) return;
    std::error_code ec;
    fs::remove(m_activation_file, ec);
}

void QuantumProofStore::LoadActivationFromFile(ChainstateManager& chainman)
{
    const fs::path path{WITH_LOCK(m_mutex, return m_activation_file)};
    if (path.empty() || !fs::exists(path)) return;

    uint256 block_hash;
    CMutableTransaction coinbase;
    std::vector<uint256> merkle_path;
    try {
        AutoFile file{fsbridge::fopen(path, "rb")};
        if (file.IsNull()) return;
        file >> block_hash >> TX_NO_WITNESS(coinbase) >> merkle_path;
    } catch (const std::exception&) {
        LogWarning("Ignoring malformed quantum activation file %s\n", fs::PathToString(path));
        return;
    }

    // Confirm the activation block is still in the active chain (it may have been
    // reorged out while the node was down). Only the header is needed, so this
    // also works for pruned nodes.
    int height;
    uint256 merkle_root;
    {
        LOCK(cs_main);
        const CBlockIndex* pindex{chainman.m_blockman.LookupBlockIndex(block_hash)};
        if (pindex == nullptr || !chainman.ActiveChain().Contains(*pindex)) {
            LogInfo("Quantum activation block %s is not in the active chain; tripwire inactive\n", block_hash.ToString());
            return;
        }
        height = pindex->nHeight;
        merkle_root = pindex->hashMerkleRoot;
    }

    // Verify the coinbase is committed in that block: fold the merkle path. The
    // coinbase is the leftmost leaf, so it stays the left operand at every level.
    uint256 root{coinbase.GetHash().ToUint256()};
    for (const uint256& step : merkle_path) {
        root = Hash(root, step);
    }
    if (root != merkle_root) {
        LogWarning("Quantum activation file %s has an invalid merkle proof; ignoring\n", fs::PathToString(path));
        return;
    }

    // Recover the proof from the (now-trusted) coinbase, re-verifying it -- a
    // defense against broken or malicious software writing a bogus coinbase.
    std::optional<std::vector<unsigned char>> found;
    for (const CTxOut& out : coinbase.vout) {
        auto proof{ProofFromScript(std::span<const unsigned char>(out.scriptPubKey.data(), out.scriptPubKey.size()))};
        if (proof && Verify(*proof)) {
            found = std::move(proof);
            break;
        }
    }
    if (!found) {
        LogWarning("Quantum activation file %s coinbase carries no valid proof; ignoring\n", fs::PathToString(path));
        return;
    }

    LOCK(m_mutex);
    m_proof = std::move(found);
    m_active_since = height + 1;
    m_activation_block = block_hash;
    LogInfo("Quantum tripwire activation restored from disk: block %d (%s); active from height %d\n",
            height, block_hash.ToString(), *m_active_since);
}

QuantumProofStore& GetQuantumProofStore()
{
    static QuantumProofStore store;
    return store;
}

} // namespace node

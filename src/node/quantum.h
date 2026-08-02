// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_QUANTUM_H
#define BITCOIN_NODE_QUANTUM_H

#include <pubkey.h>
#include <sync.h>
#include <util/fs.h>
#include <validationinterface.h>

#include <cstddef>
#include <optional>
#include <span>
#include <vector>

class CBlock;
class CBlockIndex;
class CTransaction;
class ChainstateManager;

namespace node {

//! Serialized size of an "aRsm" ECDL-break proof: a(32) || R(32) || s(32) || m(32).
static constexpr size_t QUANTUM_PROOF_SIZE{128};

/**
 * In-memory state for the "quantum tripwire" -- Anthony Towns' "aRsm" ECDL-break
 * proof from the bitcoindev thread
 * https://gnusha.org/pi/bitcoindev/aj9SkwXqdRbuVZxH@erisian.com.au/
 *
 * A 128-byte proof is the concatenation a || R || s || m. It is valid for the
 * configured NUMS point N if (R, s) is a valid BIP-340 signature of m under
 * P = N + a*G. A valid signature can only be produced by someone who knows
 * dlog(P) = dlog(N) + a; since a is part of the proof, that is equivalent to
 * knowing dlog(N), which requires breaking the elliptic-curve discrete log
 * problem on secp256k1. See test/functional/test_framework/quantum.py.
 *
 * The node holds at most ONE proof (publishing more would just bloat coinbases).
 * Once a proof is known it is published as a single required OP_RETURN output in
 * the coinbase of the next block. A block carrying the proof instantly activates
 * the "quantum" tripwire from the following block (see getdeploymentinfo); after
 * activation the proof is no longer added to templates and incoming blocks are
 * no longer scanned for it. There is no actual consensus rule change here -- the
 * activation is purely a signal that a NUMS discrete log has been published.
 *
 * Activation is detected by scanning connected blocks' coinbase outputs, so this
 * is a CValidationInterface. The activation point is persisted: when the tripwire
 * fires we write a small file with the activation block hash, the full coinbase
 * transaction, and its merkle inclusion path. At startup the file is re-read and
 * verified two ways -- the coinbase's merkle path must reconstruct the block
 * header's merkle root, and the coinbase must carry a proof that verifies -- and
 * the header is looked up to confirm it is still in the active chain. Only the
 * header is needed (not the block body), so this works for pruned nodes; and the
 * proof is recovered by scanning the coinbase, so it is not stored twice. The
 * store is a process-global singleton (each bitcoind has its own).
 */
class QuantumProofStore : public CValidationInterface
{
public:
    //! Set the NUMS point N used for verification. Defaults to the real BIP-341
    //! NUMS point (XOnlyPubKey::NUMS_H), whose discrete log is unknown.
    void SetNumsPoint(const XOnlyPubKey& nums) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    //! Switch to a fake NUMS point with a known discrete log (-test=fakenums),
    //! so tests can simulate a theft and produce a verifying proof.
    void UseFakeNumsPoint() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    XOnlyPubKey GetNumsPoint() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Return true if `proof` is well-formed and verifies against our NUMS point.
    bool Verify(std::span<const unsigned char> proof) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Verify `proof` and, if valid, store it. Returns true only if it was newly
    //! stored. A proof is ignored (returns false) if it is invalid, if we already
    //! hold a proof, or if the tripwire has already activated.
    bool Add(std::vector<unsigned char> proof) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! The stored proof, if any.
    std::optional<std::vector<unsigned char>> GetProof() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! First block height at which the tripwire is active (one past the height of
    //! the block that published the proof), or nullopt if not yet activated.
    std::optional<int> ActivationHeight() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    //! Whether the tripwire is active for a block at the given height.
    bool IsActiveAtHeight(int height) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Set the path of the file used to persist the activation point. Must be set
    //! at startup, before any block is connected.
    void SetActivationFilePath(fs::path path) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    //! Restore activation from the persisted file (if any): re-verify the proof,
    //! confirm the activation block is still in the active chain, and activate.
    void LoadActivationFromFile(ChainstateManager& chainman) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

protected:
    void BlockConnected(const kernel::ChainstateRole& role, const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex) override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void BlockDisconnected(const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex) override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    bool VerifyLocked(std::span<const unsigned char> proof) const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void WriteActivationFile(const CTransaction& coinbase, const std::vector<uint256>& merkle_path) const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void RemoveActivationFile() const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    mutable Mutex m_mutex;
    XOnlyPubKey m_nums GUARDED_BY(m_mutex){XOnlyPubKey::NUMS_H};
    std::optional<std::vector<unsigned char>> m_proof GUARDED_BY(m_mutex);
    //! Height of the first block at which the tripwire is active. Set when a block
    //! publishing the proof is connected; cleared if that block is disconnected.
    std::optional<int> m_active_since GUARDED_BY(m_mutex);
    //! Hash of the block that published the proof (for reorg handling).
    uint256 m_activation_block GUARDED_BY(m_mutex);
    //! File the activation point is persisted to (empty disables persistence).
    fs::path m_activation_file GUARDED_BY(m_mutex);
};

//! Extract a 128-byte aRsm proof from an OP_RETURN <proof> scriptPubKey, if it
//! has exactly that shape.
std::optional<std::vector<unsigned char>> ProofFromScript(std::span<const unsigned char> script);

//! Accessor for the process-global tripwire state.
QuantumProofStore& GetQuantumProofStore();

} // namespace node

#endif // BITCOIN_NODE_QUANTUM_H

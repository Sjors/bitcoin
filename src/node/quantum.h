// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_QUANTUM_H
#define BITCOIN_NODE_QUANTUM_H

#include <pubkey.h>
#include <sync.h>

#include <cstddef>
#include <optional>
#include <span>
#include <vector>

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
 * The store is a process-global singleton (each bitcoind has its own) and is not
 * persisted across restarts.
 */
class QuantumProofStore
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
    //! stored. A proof is ignored (returns false) if it is invalid or if we
    //! already hold a proof.
    bool Add(std::vector<unsigned char> proof) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! The stored proof, if any.
    std::optional<std::vector<unsigned char>> GetProof() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    bool VerifyLocked(std::span<const unsigned char> proof) const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    mutable Mutex m_mutex;
    XOnlyPubKey m_nums GUARDED_BY(m_mutex){XOnlyPubKey::NUMS_H};
    std::optional<std::vector<unsigned char>> m_proof GUARDED_BY(m_mutex);
};

//! Extract a 128-byte aRsm proof from an OP_RETURN <proof> scriptPubKey, if it
//! has exactly that shape.
std::optional<std::vector<unsigned char>> ProofFromScript(std::span<const unsigned char> script);

//! Accessor for the process-global tripwire state.
QuantumProofStore& GetQuantumProofStore();

} // namespace node

#endif // BITCOIN_NODE_QUANTUM_H

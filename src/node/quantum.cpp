// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/quantum.h>

#include <pubkey.h>
#include <script/script.h>
#include <sync.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <span>
#include <utility>

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
    if (m_proof.has_value()) return false; // we already hold a proof
    if (!VerifyLocked(proof)) return false;
    m_proof = std::move(proof);
    return true;
}

std::optional<std::vector<unsigned char>> QuantumProofStore::GetProof() const
{
    LOCK(m_mutex);
    return m_proof;
}

QuantumProofStore& GetQuantumProofStore()
{
    static QuantumProofStore store;
    return store;
}

} // namespace node

#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Helpers for the "aRsm" ECDL-break proof (the quantum tripwire).

Concept (Anthony Towns' variant, bitcoindev thread
https://gnusha.org/pi/bitcoindev/aj9SkwXqdRbuVZxH@erisian.com.au/):

  N           the BIP-341 NUMS ("Nothing Up My Sleeve") point, as an x-only
              pubkey. Because its x-coordinate falls out of a hash, nobody is
              supposed to know its discrete log.
  a           a scalar; in practice the BIP-341 Taproot tweak
                  a = hash_TapTweak(N_x || merkle_root)
              which the output's owner knows because it is a hash of public
              data (the internal key and the script tree).
  P = N + a*G the Taproot output key that appears (x-only) in the scriptPubKey.
  (R, s)      a BIP-340 Schnorr signature on a 32-byte message m, valid under P.

The 128-byte proof is the concatenation a || R || s || m. It is verified by
recomputing P = N + a*G and checking that (R, s) is a valid BIP-340 signature
of m under P. A valid signature can only be produced by someone who knows
dlog(P) = dlog(N) + a; since a is revealed in the proof, that is equivalent to
knowing dlog(N), which is only possible by breaking the elliptic-curve discrete
log problem (ECDL) on secp256k1.

In a real deployment the verifier uses the real BIP-341 NUMS point as N (see
NUMS_H below), whose discrete log is unknown. Tests substitute a *fake* NUMS
point whose discrete log is known, so an actual theft can be simulated and the
resulting proof made to verify end to end.
"""
import hashlib

from .key import (
    H_POINT,
    compute_xonly_pubkey,
    sign_schnorr,
    tweak_add_privkey,
    tweak_add_pubkey,
    verify_schnorr,
)

# The real BIP-341 NUMS point (x-only). In production this is the N the verifier
# uses; its discrete log is unknown to anyone.
NUMS_H = bytes.fromhex(H_POINT)

# A fake NUMS point whose discrete log we know, for tests. It stands in for the
# real NUMS point N so a theft -- and therefore a verifying proof -- can be
# simulated end to end. Tests start the node with -quantumnums=FAKE_NUMS_XONLY.
FAKE_NUMS_SECKEY = hashlib.sha256(b"bitcoin-quantum fake NUMS point").digest()
FAKE_NUMS_XONLY, _ = compute_xonly_pubkey(FAKE_NUMS_SECKEY)
assert FAKE_NUMS_XONLY != NUMS_H

# Byte layout of a serialized proof: a (32) || R (32) || s (32) || m (32).
PROOF_SIZE = 128


def make_proof(tweak, sig, msg):
    """Assemble a 128-byte aRsm proof from its parts.

    tweak: the 32-byte scalar a
    sig:   the 64-byte BIP-340 signature (R || s)
    msg:   the 32-byte message m that was signed
    """
    assert len(tweak) == 32
    assert len(sig) == 64
    assert len(msg) == 32
    return tweak + sig + msg


def split_proof(proof):
    """Split a 128-byte aRsm proof into (a, R, s, m)."""
    assert len(proof) == PROOF_SIZE
    return proof[0:32], proof[32:64], proof[64:96], proof[96:128]


def build_proof(nums_seckey, tweak, msg):
    """Construct a valid aRsm proof, simulating a quantum attacker.

    Signs `msg` under the output key P = N + tweak*G, where N = nums_seckey*G is
    the (fake) NUMS point whose discrete log nums_seckey we know. The result
    verifies via verify_proof() against the x-only form of N.
    """
    assert len(tweak) == 32
    assert len(msg) == 32
    output_seckey = tweak_add_privkey(nums_seckey, tweak)
    sig = sign_schnorr(output_seckey, msg)
    return make_proof(tweak, sig, msg)


def verify_proof(proof, nums=NUMS_H):
    """Return True if `proof` is a valid aRsm ECDL-break proof for NUMS point `nums`.

    This mirrors the verification the node performs: recompute P = N + a*G and
    check that (R, s) is a valid BIP-340 signature of m under P.
    """
    if len(proof) != PROOF_SIZE:
        return False
    a, R, s, m = split_proof(proof)
    res = tweak_add_pubkey(nums, a)  # P = N + a*G, returned x-only
    if res is None:
        return False
    p_xonly, _ = res
    return verify_schnorr(p_xonly, R + s, m)

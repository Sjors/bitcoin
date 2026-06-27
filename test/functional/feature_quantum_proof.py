#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Simulate a post-quantum theft and build the resulting aRsm ECDL-break proof.

See test_framework/quantum.py for the cryptographic background. This test plays
out the scenario end to end:

  1. Pick a *fake* NUMS point N = n*G whose discrete log n we know, standing in
     for the real BIP-341 NUMS point (whose discrete log nobody knows). Knowing
     n is what lets us simulate a quantum attacker that has "broken ECDL".
  2. A "victim" creates an ordinary script-path-only Taproot output that uses N
     as its internal key: scriptPubKey = OP_1 <P>, with P = N + a*G.
  3. A "quantum thief" key-path spends that output, broadcasting a BIP-340
     signature under P -- only possible if you know dlog(P) = dlog(N) + a.
  4. Anyone assembles the proof a || R || s || m from the publicly known tweak a
     and the thief's on-chain signature (R, s) over sighash m, and verifies it.
"""
import hashlib

from test_framework.key import (
    compute_xonly_pubkey,
    sign_schnorr,
    tweak_add_privkey,
)
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.quantum import (
    FAKE_NUMS_SECKEY,
    FAKE_NUMS_XONLY,
    NUMS_H,
    make_proof,
    split_proof,
    verify_proof,
)
from test_framework.script import (
    CScript,
    OP_CHECKSIG,
    taproot_construct,
    TaprootSignatureHash,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


class QuantumProofTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def simulate_theft(self):
        """Carry out the theft on-chain and return the assembled proof."""
        node = self.nodes[0]

        self.log.info("Victim creates a script-path-only Taproot output with NUMS internal key")
        # A throwaway script leaf so the output commits to a non-empty merkle
        # root; its key is irrelevant because the coin is taken via the key path.
        decoy_key, _ = compute_xonly_pubkey(hashlib.sha256(b"victim decoy leaf").digest())
        leaf_script = CScript([decoy_key, OP_CHECKSIG])
        tap = taproot_construct(FAKE_NUMS_XONLY, [("decoy", leaf_script)])
        tweak = tap.tweak  # the scalar a = hash_TapTweak(N_x || merkle_root)

        amount = 50 * COIN // 100  # 0.5 BTC
        victim_utxo = self.wallet.send_to(from_node=node, scriptPubKey=tap.scriptPubKey, amount=amount)
        self.generate(self.wallet, 1)
        self.log.info(f"Victim output P = {tap.output_pubkey.hex()} funded in {victim_utxo['txid']}")

        self.log.info("Quantum thief key-path spends the victim output")
        thief = MiniWallet(node)
        theft = CTransaction()
        theft.version = 2
        theft.vin = [CTxIn(COutPoint(int(victim_utxo["txid"], 16), victim_utxo["sent_vout"]))]
        theft.vout = [CTxOut(amount - 1000, thief.get_output_script())]
        theft.wit.vtxinwit = [CTxInWitness()]

        # The spent output, needed for the BIP-341 sighash.
        spent_outputs = [CTxOut(amount, tap.scriptPubKey)]
        # m: the message the thief signs (the Taproot key-path sighash).
        msg = TaprootSignatureHash(theft, spent_outputs, hash_type=0, input_index=0)
        # The thief, having "broken ECDL", derives dlog(P) = dlog(N) + a and signs.
        output_seckey = tweak_add_privkey(FAKE_NUMS_SECKEY, tweak)
        sig = sign_schnorr(output_seckey, msg)  # (R || s)
        theft.wit.vtxinwit[0].scriptWitness.stack = [sig]

        # The theft is a valid spend: the network accepts and mines it.
        node.sendrawtransaction(theft.serialize().hex())
        self.generate(self.wallet, 1)
        assert_equal(node.getmempoolinfo()["size"], 0)
        self.log.info(f"Coins stolen in {theft.txid_hex}")

        # a is public (anyone who knows the address construction can recompute
        # it); (R, s) is read off the thief's witness; m is the sighash.
        return make_proof(tweak, sig, msg)

    def check_proof_crypto(self, proof):
        self.log.info("Assemble the aRsm proof from public data and verify it (in Python)")
        assert_equal(len(proof), 128)
        split_proof(proof)
        # The proof verifies against our (fake) NUMS point: it demonstrates
        # knowledge of dlog(N), i.e. that ECDL was broken.
        assert verify_proof(proof, nums=FAKE_NUMS_XONLY)
        # A tampered proof, or one checked against a different NUMS point, fails.
        bad = bytearray(proof)
        bad[80] ^= 1
        assert not verify_proof(bytes(bad), nums=FAKE_NUMS_XONLY)
        assert not verify_proof(proof, nums=NUMS_H)
        assert not verify_proof(proof[:-1], nums=FAKE_NUMS_XONLY)

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.generate(self.wallet, 101)  # mature a coinbase to fund the victim

        proof = self.simulate_theft()
        self.check_proof_crypto(proof)

        self.log.info("Quantum theft simulated and aRsm proof verified")


if __name__ == '__main__':
    QuantumProofTest(__file__).main()

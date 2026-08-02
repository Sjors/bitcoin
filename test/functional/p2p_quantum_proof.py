#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Relay of "aRsm" ECDL-break (quantum tripwire) proofs over the p2p network.

A peer sends QPROOF messages. The node:
  - ignores a malformed (wrong size) proof,
  - ignores a bogus proof whose signature does not verify,
  - stores the first valid proof and publishes it as a single coinbase OP_RETURN
    in the next block, instantly activating the "quantum" deployment,
  - ignores any further proofs received over p2p once one is held.

It also relays a proof submitted locally via submitquantumproof to its peers --
even when a proof is already held -- whereas the p2p path stops at the first.

See test_framework/quantum.py for the cryptographic background, and
feature_quantum_proof.py for the on-chain theft scenario that produces such a
proof in the wild. Here valid proofs are constructed synthetically (we know the
discrete log of the fake NUMS point the node uses under -test=fakenums).
"""
import hashlib

from test_framework.messages import msg_qproof
from test_framework.p2p import (
    P2PInterface,
    p2p_lock,
)
from test_framework.quantum import (
    FAKE_NUMS_SECKEY,
    FAKE_NUMS_XONLY,
    build_proof,
    verify_proof,
)
from test_framework.script import CScript, OP_RETURN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


class QuantumProofP2PTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Verify proofs against the fake NUMS point we can sign for.
        self.extra_args = [["-test=fakenums"]]

    def coinbase_outputs(self, blockhash):
        block = self.nodes[0].getblock(blockhash, 2)
        return [out["scriptPubKey"]["hex"] for out in block["tx"][0]["vout"]]

    def make_valid_proof(self, salt):
        tweak = hashlib.sha256(b"p2p quantum proof tweak" + salt).digest()
        msg = hashlib.sha256(b"p2p quantum proof message" + salt).digest()
        proof = build_proof(FAKE_NUMS_SECKEY, tweak, msg)
        assert verify_proof(proof, nums=FAKE_NUMS_XONLY)
        return proof

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)

        proof = self.make_valid_proof(b"1")
        expected_spk = CScript([OP_RETURN, proof]).hex()
        peer = node.add_p2p_connection(P2PInterface())

        self.log.info("A malformed (wrong-size) qproof is ignored")
        peer.send_and_ping(msg_qproof(proof[:-1]))
        assert_equal(node.getquantumproof(), {"active": False})

        self.log.info("A bogus qproof (signature does not verify) is ignored")
        bogus = bytearray(proof)
        bogus[64] ^= 1  # corrupt s
        assert not verify_proof(bytes(bogus), nums=FAKE_NUMS_XONLY)
        peer.send_and_ping(msg_qproof(bytes(bogus)))
        assert_equal(node.getquantumproof(), {"active": False})

        self.log.info("A block mined while only fakes were seen has no proof OP_RETURN")
        pre_hash = self.generate(self.wallet, 1)[0]
        assert expected_spk not in self.coinbase_outputs(pre_hash)

        self.log.info("A valid qproof received over p2p is stored")
        peer.send_and_ping(msg_qproof(proof))
        self.wait_until(lambda: node.getquantumproof().get("proof") == proof.hex())

        self.log.info("submitquantumproof relays to peers even when a proof is already held")
        with p2p_lock:
            peer.last_message.pop("qproof", None)
        assert_equal(node.submitquantumproof(proof.hex()), {"valid": True, "stored": False})
        peer.wait_until(lambda: "qproof" in peer.last_message)
        with p2p_lock:
            assert_equal(peer.last_message["qproof"].proof, proof)

        self.log.info("A different valid proof received over p2p is ignored while one is held")
        peer.send_and_ping(msg_qproof(self.make_valid_proof(b"2")))
        assert_equal(node.getquantumproof().get("proof"), proof.hex())

        self.log.info("The next mined block carries the relayed proof and activates the tripwire")
        activating_hash = self.generate(self.wallet, 1)[0]
        assert expected_spk in self.coinbase_outputs(activating_hash)
        assert_equal(node.getdeploymentinfo()["deployments"]["quantum"]["active"], True)

        self.log.info("After activation, later blocks no longer carry the proof OP_RETURN")
        peer.send_and_ping(msg_qproof(self.make_valid_proof(b"3")))
        post_hash = self.generate(self.wallet, 1)[0]
        assert expected_spk not in self.coinbase_outputs(post_hash)

        self.log.info("Fakes ignored; first valid proof relayed, published once, tripwire activated")


if __name__ == '__main__':
    QuantumProofP2PTest(__file__).main()

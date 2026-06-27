#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Simulate a post-quantum theft, build the resulting aRsm ECDL-break proof, and
exercise the node's handling of it (RPC submission, coinbase publication via both
the monolithic miner and the Mining IPC, and the instant "quantum" tripwire
activation).

See test_framework/quantum.py for the cryptographic background. This test:

  1. Runs the node with -test=fakenums, so its verifier uses a NUMS point N = n*G
     whose discrete log n we know (standing in for the real BIP-341 NUMS point,
     whose discrete log nobody knows). Knowing n is what lets us simulate a
     quantum attacker that has "broken ECDL".
  2. A "victim" creates an ordinary script-path-only Taproot output that uses N
     as its internal key: scriptPubKey = OP_1 <P>, with P = N + a*G.
  3. A "quantum thief" key-path spends that output, broadcasting a BIP-340
     signature under P -- only possible if you know dlog(P) = dlog(N) + a.
  4. The proof a || R || s || m is assembled from the public tweak a and the
     thief's on-chain signature (R, s) over sighash m, and submitted via RPC.
  5. The node publishes it as a single coinbase OP_RETURN in the next block --
     verified both via the monolithic miner and (when IPC is available) via the
     Mining IPC getCoinbaseTx() requiredOutputs -- which instantly activates the
     "quantum" deployment. After activation the OP_RETURN is no longer added.
"""
import asyncio
import hashlib
from io import BytesIO

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
    OP_RETURN,
    taproot_construct,
    TaprootSignatureHash,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

# The Mining IPC check is optional: it needs both a multiprocess build and the
# python capnp module. When either is missing we still run the rest of the demo.
try:
    import capnp  # type: ignore[import] # noqa: F401
    from test_framework.ipc_util import (
        destroying,
        load_capnp_modules,
        make_mining_ctx,
        mining_get_coinbase_tx,
    )
    HAVE_CAPNP = True
except ImportError:
    HAVE_CAPNP = False


class QuantumProofTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Verify proofs against a NUMS point whose discrete log we know.
        self.extra_args = [["-test=fakenums"]]

    def setup_nodes(self):
        # Bind the IPC socket so we can also demonstrate the proof flowing through
        # the Mining IPC, when both IPC and python capnp are available.
        self.ipc = self.is_ipc_compiled() and HAVE_CAPNP
        if self.ipc:
            self.extra_init = [{"ipcbind": True}]
        super().setup_nodes()
        if self.ipc:
            self.capnp_modules = load_capnp_modules(self.config)

    def simulate_theft(self):
        """Carry out the theft on-chain and return (proof, expected_op_return_spk)."""
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
        proof = make_proof(tweak, sig, msg)
        expected_spk = CScript([OP_RETURN, proof])
        return proof, expected_spk

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

    def coinbase_outputs(self, blockhash):
        """Return the list of coinbase scriptPubKey hexes for a block."""
        block = self.nodes[0].getblock(blockhash, 2)
        return [out["scriptPubKey"]["hex"] for out in block["tx"][0]["vout"]]

    def check_ipc_coinbase(self, expected_spk):
        """A mining client driving the node over IPC must include the proof OP_RETURN."""
        if not self.ipc:
            self.log.info("IPC unavailable; skipping the Mining IPC coinbase check")
            return
        self.log.info("The Mining IPC getCoinbaseTx() lists the proof as a required output")

        async def async_routine():
            ctx, mining = await make_mining_ctx(self)
            opts = self.capnp_modules['mining'].BlockCreateOptions()
            async with destroying((await mining.createNewBlock(ctx, opts)).result, ctx) as template:
                coinbase_res = await mining_get_coinbase_tx(template, ctx)
                scripts = []
                for output_data in coinbase_res.requiredOutputs:
                    out = CTxOut()
                    out.deserialize(BytesIO(output_data))
                    scripts.append(bytes(out.scriptPubKey))
                assert bytes(expected_spk) in scripts, "IPC coinbase should require the proof OP_RETURN"

        asyncio.run(capnp.run(async_routine()))

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.generate(self.wallet, 101)  # mature a coinbase to fund the victim

        proof, expected_spk = self.simulate_theft()
        self.check_proof_crypto(proof)

        self.log.info("Before any proof is submitted, the node holds none and is inactive")
        assert_equal(node.getquantumproof(), {"active": False})

        self.log.info("A block mined before any proof is submitted has no proof OP_RETURN")
        pre_hash = self.generate(self.wallet, 1)[0]
        assert expected_spk.hex() not in self.coinbase_outputs(pre_hash)

        self.log.info("A bogus proof is rejected by submitquantumproof and not stored")
        bogus = (b"\x00" * 96) + proof[96:]  # invalid signature, real message
        assert_equal(node.submitquantumproof(bogus.hex()), {"valid": False, "stored": False})
        assert_equal(node.getquantumproof(), {"active": False})

        self.log.info("The real proof is accepted and stored; a second proof is ignored")
        assert_equal(node.submitquantumproof(proof.hex()), {"valid": True, "stored": True})
        # Re-submitting verifies but is not stored again (we already hold one).
        assert_equal(node.submitquantumproof(proof.hex()), {"valid": True, "stored": False})
        assert_equal(node.getquantumproof(), {"proof": proof.hex(), "active": False})

        # Before activation, a mining client building the coinbase over IPC sees
        # the proof among the required outputs.
        self.check_ipc_coinbase(expected_spk)

        self.log.info("The next mined block carries the proof and activates the tripwire")
        activating_hash = self.generate(self.wallet, 1)[0]
        assert expected_spk.hex() in self.coinbase_outputs(activating_hash)
        activation_height = node.getblock(activating_hash)["height"] + 1
        assert_equal(node.getquantumproof(), {"proof": proof.hex(), "active": True, "activation_height": activation_height})

        self.log.info("After activation, later blocks no longer carry the proof OP_RETURN")
        post_hash = self.generate(self.wallet, 1)[0]
        assert expected_spk.hex() not in self.coinbase_outputs(post_hash)

        self.log.info("After activation, further proofs are ignored")
        assert_equal(node.submitquantumproof(proof.hex()), {"valid": True, "stored": False})

        self.log.info("Activation persists across a restart (restored from the activation file)")
        self.restart_node(0, extra_args=["-test=fakenums"])
        assert_equal(node.getquantumproof(), {"proof": proof.hex(), "active": True, "activation_height": activation_height})

        self.log.info("Reorging a block mined *after* activation does not deactivate the tripwire")
        _, later_hash = self.generate(self.wallet, 2)
        node.invalidateblock(later_hash)  # rolls back a non-activation block
        # The store tracks activation via the (asynchronous) validation interface,
        # so drain its queue before reading the tripwire state back.
        node.syncwithvalidationinterfacequeue()
        assert_equal(node.getquantumproof()["active"], True)
        node.reconsiderblock(later_hash)

        self.log.info("Reorging the activation block itself deactivates the tripwire")
        node.invalidateblock(activating_hash)
        node.syncwithvalidationinterfacequeue()
        assert_equal(node.getquantumproof()["active"], False)
        node.reconsiderblock(activating_hash)  # reconnecting re-activates it
        node.syncwithvalidationinterfacequeue()
        assert_equal(node.getquantumproof()["active"], True)

        self.log.info("A bogus activation file is rejected at startup")
        self.stop_node(0)
        # Garbage that doesn't reference a real block with a merkle-committed,
        # proof-bearing coinbase, as broken/malicious software might write.
        (node.chain_path / "quantum_tripwire.dat").write_bytes(b"\x00" * 64)
        self.start_node(0, extra_args=["-test=fakenums"])
        assert_equal(node.getquantumproof(), {"active": False})

        self.log.info("Quantum theft simulated; proof published once and tripwire activated instantly")


if __name__ == '__main__':
    QuantumProofTest(__file__).main()

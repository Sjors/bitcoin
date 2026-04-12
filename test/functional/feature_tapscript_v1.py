#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test experimental tapscript v1 (leaf version 0xc2) with 4KB stack element size."""

import os
import random

from test_framework.blocktools import (
    COINBASE_MATURITY,
    create_coinbase,
    create_block,
    add_witness_commitment,
    MAX_BLOCK_SIGOPS_WEIGHT,
)
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    SEQUENCE_FINAL,
    tx_from_hex,
    WITNESS_SCALE_FACTOR,
)
from test_framework.script import (
    CScript,
    LEAF_VERSION_TAPSCRIPT,
    LEAF_VERSION_TAPSCRIPT_V1,
    MAX_SCRIPT_ELEMENT_SIZE,
    OP_1,
    OP_CHECKSIG,
    OP_DROP,
    OP_DUP,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_SIZE,
    OP_SWAP,
    OP_TRUE,
    SIGHASH_DEFAULT,
    TaggedHash,
    TaprootSignatureHash,
    taproot_construct,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.key import (
    generate_privkey,
    compute_xonly_pubkey,
    sign_schnorr,
)

# 4KB limit for tapscript v1
MAX_SCRIPT_ELEMENT_SIZE_V1 = 4096


class TapscriptV1Test(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def build_control_block(self, tap, leaf_name):
        """Build a control block for the given leaf."""
        leaf = tap.leaves[leaf_name]
        return bytes([leaf.version + tap.negflag]) + tap.internal_pubkey + leaf.merklebranch

    def create_taproot_utxo(self, node, tap, amount=100_000):
        """Fund a taproot output and return (txid_int, vout, amount)."""
        # Use fundrawtransaction to build a tx paying to tap.scriptPubKey
        raw_tx = node.createrawtransaction([], [{node.getnewaddress(): amount / 1e8}])
        funded = node.fundrawtransaction(raw_tx, {"changePosition": 1})
        # Replace the first output with our taproot scriptPubKey
        decoded = node.decoderawtransaction(funded["hex"])
        fund_tx = tx_from_hex(funded["hex"])
        fund_tx.vout[0].scriptPubKey = tap.scriptPubKey
        fund_tx.vout[0].nValue = amount
        signed = node.signrawtransactionwithwallet(fund_tx.serialize().hex())
        assert signed["complete"]
        fund_tx = tx_from_hex(signed["hex"])

        # Mine via block
        self.submit_block_with_tx(node, fund_tx)
        return fund_tx.txid_int, 0, amount

    def submit_block_with_tx(self, node, tx, accept=True):
        """Submit a block containing the given transaction."""
        tip = int(node.getbestblockhash(), 16)
        height = node.getblockcount() + 1
        block_time = node.getblock(node.getbestblockhash())["time"] + 1
        coinbase = create_coinbase(height)
        block = create_block(tip, coinbase, block_time, txlist=[tx])
        add_witness_commitment(block)
        block.solve()
        result = node.submitblock(block.serialize().hex())
        if accept:
            assert_equal(node.getbestblockhash(), block.hash_hex)
        return result

    def make_tapscript_spend(self, node, tap, leaf_name, witness_items, txid, vout, amount,
                             sign=True, sec=None, fee=1000, leaf_ver=LEAF_VERSION_TAPSCRIPT_V1):
        """Build a transaction spending a taproot UTXO via script path.

        witness_items: list of bytes to put on the stack before script+controlblock
        sign: if True, the first witness item is replaced with a Schnorr signature
        """
        leaf = tap.leaves[leaf_name]
        control_block = self.build_control_block(tap, leaf_name)

        prev_out = CTxOut(amount, tap.scriptPubKey)

        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(txid, vout), nSequence=SEQUENCE_FINAL)]
        # Send to OP_TRUE for simplicity
        tx.vout = [CTxOut(amount - fee, CScript([OP_TRUE]))]
        tx.wit.vtxinwit = [CTxInWitness()]

        if sign and sec is not None:
            # Compute script-path sighash
            sighash = TaprootSignatureHash(
                tx, [prev_out], SIGHASH_DEFAULT, input_index=0,
                scriptpath=True, leaf_script=leaf.script, leaf_ver=leaf_ver,
                codeseparator_pos=0xFFFFFFFF
            )
            sig = sign_schnorr(sec, sighash)
            witness_items = [sig] + witness_items

        # Witness stack: [items...] + [script] + [control_block]
        tx.wit.vtxinwit[0].scriptWitness.stack = witness_items + [leaf.script, control_block]
        return tx

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, COINBASE_MATURITY + 10)

        self.log.info("Generating keys...")
        sec = generate_privkey()
        pub, _ = compute_xonly_pubkey(sec)

        self.test_large_witness_input(node, sec, pub)
        self.test_large_push_in_script(node, sec, pub)
        self.test_521_byte_element_rejected_v0(node, sec, pub)
        self.test_521_byte_element_accepted_v1(node, sec, pub)
        self.test_4097_byte_element_rejected_v1(node, sec, pub)
        self.test_boundary_520_521_4096(node, sec, pub)
        self.test_large_witness_stack_item(node, sec, pub)
        self.test_backward_compat_v0_script_push(node, sec, pub)
        self.test_backward_compat_v0_after_v1(node, sec, pub)

    def test_large_witness_input(self, node, sec, pub):
        """Test spending with a 2KB witness stack element under tapscript v1."""
        self.log.info("Test: 2KB witness input accepted under tapscript v1")

        big_data = random.randbytes(2048)

        # Script: OP_SIZE <2048> OP_EQUALVERIFY OP_DROP OP_<pubkey> OP_CHECKSIG
        # Witness: [sig, big_data]
        script = CScript([OP_SIZE, len(big_data)] + [OP_EQUALVERIFY, OP_DROP, pub, OP_CHECKSIG])
        scripts = [("big_input", script, LEAF_VERSION_TAPSCRIPT_V1)]
        tap = taproot_construct(pub, scripts)

        txid, vout, amount = self.create_taproot_utxo(node, tap)

        tx = self.make_tapscript_spend(
            node, tap, "big_input", [big_data],
            txid, vout, amount, sign=True, sec=sec,
        )

        result = self.submit_block_with_tx(node, tx)
        self.log.info("  -> Accepted (block result: %s)" % result)

    def test_large_push_in_script(self, node, sec, pub):
        """Test a script that pushes a 4KB element onto the stack under tapscript v1."""
        self.log.info("Test: 4KB push in script accepted under tapscript v1")

        big_data = random.randbytes(4096)

        # Script: <4096 bytes> OP_DROP <pubkey> OP_CHECKSIG
        script = CScript([big_data, OP_DROP, pub, OP_CHECKSIG])
        scripts = [("big_push", script, LEAF_VERSION_TAPSCRIPT_V1)]
        tap = taproot_construct(pub, scripts)

        txid, vout, amount = self.create_taproot_utxo(node, tap)

        tx = self.make_tapscript_spend(
            node, tap, "big_push", [],
            txid, vout, amount, sign=True, sec=sec,
        )

        result = self.submit_block_with_tx(node, tx)
        self.log.info("  -> Accepted (block result: %s)" % result)

    def test_521_byte_element_rejected_v0(self, node, sec, pub):
        """Test that a 521-byte witness element is rejected under tapscript v0."""
        self.log.info("Test: 521-byte witness input rejected under tapscript v0 (leaf 0xc0)")

        big_data = random.randbytes(521)

        # Script: OP_DROP <pubkey> OP_CHECKSIG (under v0)
        script = CScript([OP_DROP, pub, OP_CHECKSIG])
        scripts = [("drop_input", script, LEAF_VERSION_TAPSCRIPT)]
        tap = taproot_construct(pub, scripts)

        txid, vout, amount = self.create_taproot_utxo(node, tap)

        tx = self.make_tapscript_spend(
            node, tap, "drop_input", [big_data],
            txid, vout, amount, sign=True, sec=sec,
            leaf_ver=LEAF_VERSION_TAPSCRIPT,
        )

        result = self.submit_block_with_tx(node, tx, accept=False)
        assert result is not None and "script-verify-flag-failed" in result
        self.log.info("  -> Correctly rejected")

    def test_521_byte_element_accepted_v1(self, node, sec, pub):
        """Test that a 521-byte witness element is accepted under tapscript v1."""
        self.log.info("Test: 521-byte witness input accepted under tapscript v1 (leaf 0xc2)")

        big_data = random.randbytes(521)

        # Script: OP_DROP <pubkey> OP_CHECKSIG (under v1)
        script = CScript([OP_DROP, pub, OP_CHECKSIG])
        scripts = [("drop_input", script, LEAF_VERSION_TAPSCRIPT_V1)]
        tap = taproot_construct(pub, scripts)

        txid, vout, amount = self.create_taproot_utxo(node, tap)

        tx = self.make_tapscript_spend(
            node, tap, "drop_input", [big_data],
            txid, vout, amount, sign=True, sec=sec,
        )

        result = self.submit_block_with_tx(node, tx)
        self.log.info("  -> Accepted (block result: %s)" % result)

    def test_4097_byte_element_rejected_v1(self, node, sec, pub):
        """Test that a 4097-byte witness element is rejected even under tapscript v1."""
        self.log.info("Test: 4097-byte witness input rejected under tapscript v1")

        big_data = random.randbytes(4097)

        # Script: OP_DROP <pubkey> OP_CHECKSIG (under v1)
        script = CScript([OP_DROP, pub, OP_CHECKSIG])
        scripts = [("drop_input", script, LEAF_VERSION_TAPSCRIPT_V1)]
        tap = taproot_construct(pub, scripts)

        txid, vout, amount = self.create_taproot_utxo(node, tap)

        tx = self.make_tapscript_spend(
            node, tap, "drop_input", [big_data],
            txid, vout, amount, sign=True, sec=sec,
        )

        result = self.submit_block_with_tx(node, tx, accept=False)
        assert result is not None and "script-verify-flag-failed" in result
        self.log.info("  -> Correctly rejected")

    def test_boundary_520_521_4096(self, node, sec, pub):
        """Test exact boundary values: 520 OK on both, 521 fails v0 passes v1, 4096 passes v1."""
        self.log.info("Test: boundary values 520/521/4096 bytes")

        for size, leaf_ver, should_accept, label in [
            (520,  LEAF_VERSION_TAPSCRIPT,    True,  "520B on v0"),
            (520,  LEAF_VERSION_TAPSCRIPT_V1, True,  "520B on v1"),
            (521,  LEAF_VERSION_TAPSCRIPT,    False, "521B on v0"),
            (521,  LEAF_VERSION_TAPSCRIPT_V1, True,  "521B on v1"),
            (4096, LEAF_VERSION_TAPSCRIPT_V1, True,  "4096B on v1"),
            (4097, LEAF_VERSION_TAPSCRIPT_V1, False, "4097B on v1"),
        ]:
            self.log.info("  Sub-test: %s (expect %s)" % (label, "accept" if should_accept else "reject"))

            data = random.randbytes(size)
            script = CScript([OP_DROP, pub, OP_CHECKSIG])
            scripts = [("boundary", script, leaf_ver)]
            tap = taproot_construct(pub, scripts)

            txid, vout, amount = self.create_taproot_utxo(node, tap)

            tx = self.make_tapscript_spend(
                node, tap, "boundary", [data],
                txid, vout, amount, sign=True, sec=sec,
                leaf_ver=leaf_ver,
            )

            result = self.submit_block_with_tx(node, tx, accept=should_accept)
            if should_accept:
                assert result is None or result == "duplicate", "Expected accept for %s, got: %s" % (label, result)
            else:
                assert result is not None and "script-verify-flag-failed" in result, \
                    "Expected reject for %s, got: %s" % (label, result)
            self.log.info("    -> OK")

    def test_large_witness_stack_item(self, node, sec, pub):
        """Test spending with a full 4KB data element verified by duplication and comparison."""
        self.log.info("Test: 4KB element dup+equal under tapscript v1")

        big_data = random.randbytes(4096)

        # Script: OP_DUP OP_EQUAL — requires two copies of the same element on the stack
        # Witness provides: [big_data, big_data, sig] but we need script to use it:
        # Script: OP_SWAP OP_EQUALVERIFY <pubkey> OP_CHECKSIG
        # Witness: [sig, big_data, big_data]
        script = CScript([OP_SWAP, OP_EQUALVERIFY, pub, OP_CHECKSIG])
        scripts = [("dup_check", script, LEAF_VERSION_TAPSCRIPT_V1)]
        tap = taproot_construct(pub, scripts)

        txid, vout, amount = self.create_taproot_utxo(node, tap)

        tx = self.make_tapscript_spend(
            node, tap, "dup_check", [big_data, big_data],
            txid, vout, amount, sign=True, sec=sec,
        )

        result = self.submit_block_with_tx(node, tx)
        self.log.info("  -> Accepted (block result: %s)" % result)

    def test_backward_compat_v0_script_push(self, node, sec, pub):
        """Backward-compat: a 521-byte literal push in script is rejected under tapscript v0.

        This exercises the push-size check inside EvalScript (not the witness
        stack item check in ExecuteWitnessScript) and verifies the v1 changes
        did not loosen the v0 code path.
        """
        self.log.info("Test: backward-compat — 521-byte script push rejected under v0")

        big_data = random.randbytes(521)

        # Script embeds the oversized push directly; witness has only sig + script + control
        script = CScript([big_data, OP_DROP, pub, OP_CHECKSIG])
        scripts = [("v0_big_push", script, LEAF_VERSION_TAPSCRIPT)]
        tap = taproot_construct(pub, scripts)

        txid, vout, amount = self.create_taproot_utxo(node, tap)

        tx = self.make_tapscript_spend(
            node, tap, "v0_big_push", [],
            txid, vout, amount, sign=True, sec=sec,
            leaf_ver=LEAF_VERSION_TAPSCRIPT,
        )

        result = self.submit_block_with_tx(node, tx, accept=False)
        assert result is not None and "script-verify-flag-failed" in result, \
            "521-byte script push should be rejected under v0, got: %s" % result
        self.log.info("  -> Correctly rejected")

    def test_backward_compat_v0_after_v1(self, node, sec, pub):
        """Backward-compat: accept a 4KB element under v1, then verify v0 still rejects 521B.

        Guards against accidental state leak (e.g. m_max_script_element_size
        being cached/shared) between executions.
        """
        self.log.info("Test: backward-compat — v0 still strict after a v1 spend in same block")

        # --- First: a valid v1 spend with a 4096-byte witness item ---
        big_v1 = random.randbytes(4096)
        script_v1 = CScript([OP_DROP, pub, OP_CHECKSIG])
        scripts_v1 = [("v1_ok", script_v1, LEAF_VERSION_TAPSCRIPT_V1)]
        tap_v1 = taproot_construct(pub, scripts_v1)
        txid_v1, vout_v1, amount_v1 = self.create_taproot_utxo(node, tap_v1)

        tx_v1 = self.make_tapscript_spend(
            node, tap_v1, "v1_ok", [big_v1],
            txid_v1, vout_v1, amount_v1, sign=True, sec=sec,
        )

        result = self.submit_block_with_tx(node, tx_v1)
        assert result is None or result == "duplicate", \
            "v1 4096-byte spend should succeed, got: %s" % result
        self.log.info("  -> v1 spend accepted")

        # --- Second: a v0 spend with a 521-byte witness item must still fail ---
        bad_v0 = random.randbytes(521)
        script_v0 = CScript([OP_DROP, pub, OP_CHECKSIG])
        scripts_v0 = [("v0_bad", script_v0, LEAF_VERSION_TAPSCRIPT)]
        tap_v0 = taproot_construct(pub, scripts_v0)
        txid_v0, vout_v0, amount_v0 = self.create_taproot_utxo(node, tap_v0)

        tx_v0 = self.make_tapscript_spend(
            node, tap_v0, "v0_bad", [bad_v0],
            txid_v0, vout_v0, amount_v0, sign=True, sec=sec,
            leaf_ver=LEAF_VERSION_TAPSCRIPT,
        )

        result = self.submit_block_with_tx(node, tx_v0, accept=False)
        assert result is not None and "script-verify-flag-failed" in result, \
            "521-byte element under v0 must still be rejected after v1 spend, got: %s" % result
        self.log.info("  -> v0 correctly rejected after v1 spend")


if __name__ == '__main__':
    TapscriptV1Test(__file__).main()

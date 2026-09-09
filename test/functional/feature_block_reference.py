#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test witness v2 Taproot outputs (BIP341/342 semantics plus block references).

A witness v2 output is spent exactly like a v1 Taproot output. In addition, an
input may carry an annex with a block reference; the signature message then
commits to the hash of the referenced block (see doc/block-reference.md).
"""

from test_framework.blocktools import (
    COINBASE_MATURITY,
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.key import (
    ECKey,
    compute_xonly_pubkey,
    sign_schnorr,
    tweak_add_privkey,
)
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.script import (
    CScript,
    OP_CHECKSIG,
    TaprootSignatureHash,
    block_ref_annex,
    taproot_construct,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet

FEE = 1000
AMOUNT = 100_000


class V2Coin:
    """A witness v2 output funded from the MiniWallet, with everything needed to spend it."""

    def __init__(self, test, node, amount=AMOUNT):
        self.node = node
        self.key = ECKey()
        self.key.generate()
        self.seckey = self.key.get_bytes()
        self.pubkey = compute_xonly_pubkey(self.seckey)[0]
        self.leaf_script = CScript([self.pubkey, OP_CHECKSIG])
        self.tap = taproot_construct(self.pubkey, [("leaf", self.leaf_script)], witver=2)
        self.amount = amount
        funding = test.wallet.send_to(from_node=node, scriptPubKey=self.tap.scriptPubKey, amount=amount)
        test.generate(node, 1)
        self.outpoint = COutPoint(int(funding["txid"], 16), funding["sent_vout"])
        self.utxo = CTxOut(amount, self.tap.scriptPubKey)

    def spend(self, test, *, scriptpath=False, ref_height=None, block_hash=None, annex=None):
        """Build a transaction spending this coin back to the MiniWallet.

        ref_height: put a block reference annex for this height in the witness.
        block_hash: the hash committed to by the signature (defaults to the hash
                    at ref_height on self.node); pass a different one to sign
                    for another chain.
        annex: raw annex to use instead of the block reference one.
        """
        tx = CTransaction()
        tx.vin = [CTxIn(self.outpoint)]
        tx.vout = [CTxOut(self.amount - FEE, test.wallet.get_output_script())]
        if ref_height is not None:
            annex = block_ref_annex(ref_height)
            if block_hash is None:
                block_hash = bytes.fromhex(self.node.getblockhash(ref_height))[::-1]
        if scriptpath:
            leaf = self.tap.leaves["leaf"]
            sighash = TaprootSignatureHash(tx, [self.utxo], 0, scriptpath=True, leaf_script=self.leaf_script, codeseparator_pos=0xFFFFFFFF, annex=annex, block_hash=block_hash)
            control = bytes([leaf.version + self.tap.negflag]) + self.tap.internal_pubkey + leaf.merklebranch
            stack = [sign_schnorr(self.seckey, sighash), self.leaf_script, control]
        else:
            sighash = TaprootSignatureHash(tx, [self.utxo], 0, annex=annex, block_hash=block_hash)
            stack = [sign_schnorr(tweak_add_privkey(self.seckey, self.tap.tweak), sighash)]
        if annex is not None:
            stack.append(annex)
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = stack
        return tx


class BlockReferenceTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def submit_block(self, node, txs):
        """Mine a block containing txs on top of node's tip; return submitblock's result (None if accepted)."""
        height = node.getblockcount() + 1
        block = create_block(int(node.getbestblockhash(), 16), create_coinbase(height), txlist=txs, ntime=node.getblock(node.getbestblockhash())["time"] + 1)
        add_witness_commitment(block)
        block.solve()
        result = node.submitblock(block.serialize().hex())
        if result is None:
            self.sync_blocks()
        return result

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.test_v2_spends()

    def test_v2_spends(self):
        self.log.info("Witness v2 outputs spend like Taproot")
        node = self.nodes[0]
        for scriptpath in (False, True):
            coin = V2Coin(self, node)
            tx = coin.spend(self, scriptpath=scriptpath)
            # Not standard yet, so mine it directly
            assert_equal(self.submit_block(node, [tx]), None)
            assert_equal(node.gettxout(tx.txid_hex, 0)["confirmations"], 1)
            # An invalid signature is rejected (v2 is not anyone-can-spend)
            bad = V2Coin(self, node).spend(self, scriptpath=scriptpath)
            bad.wit.vtxinwit[0].scriptWitness.stack[0] = bytes(64)
            assert_equal(self.submit_block(node, [bad]), "block-script-verify-flag-failed (Invalid Schnorr signature)")


if __name__ == '__main__':
    BlockReferenceTest(__file__).main()

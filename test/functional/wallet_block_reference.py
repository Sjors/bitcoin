#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test wallet support for witness v2 (tr2) outputs and block references.

The wallet receives to tr2() descriptors and, when asked with the
block_reference option, spends with an annex referencing the block at
tip - 99 (see doc/block-reference.md), both through send/sendall and
through the PSBT workflow.
"""

from decimal import Decimal

from test_framework.address import address_to_scriptpubkey
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.psbt import PSBT
from test_framework.script import block_ref_annex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet


class WalletBlockReferenceTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def check_annexes(self, txid, expect_reference):
        """Every input of the (in-mempool) transaction spends a tr2 output; check the block reference annex."""
        node = self.nodes[0]
        tx = node.getrawtransaction(txid, True)
        expected = block_ref_annex(node.getblockcount() - (COINBASE_MATURITY - 1)).hex()
        for vin in tx["vin"]:
            witness = vin["txinwitness"]
            if expect_reference:
                assert_equal(len(witness), 2)
                assert_equal(witness[1], expected)
            else:
                assert_equal(len(witness), 1)

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("w")
        w = node.get_wallet_rpc("w")

        self.log.info("Import tr2() descriptors derived from the wallet's tr() descriptors")
        for desc in w.listdescriptors(True)["descriptors"]:
            if not desc["desc"].startswith("tr("):
                continue
            tr2 = "tr2(" + desc["desc"][len("tr("):].split("#")[0]
            tr2 += "#" + node.getdescriptorinfo(tr2)["checksum"]
            res = w.importdescriptors([{"desc": tr2, "active": True, "internal": desc["internal"], "timestamp": "now"}])
            assert_equal(res[0]["success"], True)
        addr = w.getnewaddress(address_type="bech32m")
        assert addr.startswith("bcrt1z")  # witness v2
        assert_equal(w.getaddressinfo(addr)["desc"].startswith("tr2("), True)

        miniwallet = MiniWallet(node)
        for _ in range(3):
            miniwallet.send_to(from_node=node, scriptPubKey=address_to_scriptpubkey(addr), amount=1_000_000)
        self.generate(node, 1)
        assert_equal(w.getbalance(), Decimal("0.03"))

        self.log.info("send with block_reference adds the annex to every input")
        res = w.send({addr: Decimal("0.005")}, options={"block_reference": True})
        assert_equal(res["complete"], True)
        self.check_annexes(res["txid"], True)
        self.generate(node, 1)
        assert_equal(w.gettransaction(res["txid"])["confirmations"], 1)

        self.log.info("send without the option spends without an annex")
        res = w.send({addr: Decimal("0.005")})
        self.check_annexes(res["txid"], False)
        self.generate(node, 1)

        self.log.info("sendall with block_reference")
        res = w.sendall([addr], options={"block_reference": True})
        self.check_annexes(res["txid"], True)
        self.generate(node, 1)

        self.log.info("PSBT workflow carries the reference through walletcreatefundedpsbt, walletprocesspsbt and finalizepsbt")
        tip = node.getblockcount()
        res = w.walletcreatefundedpsbt([], {addr: Decimal("0.004")}, 0, {"block_reference": True})
        for psbt_input in node.decodepsbt(res["psbt"])["inputs"]:
            assert_equal(psbt_input["block_reference"], {"height": tip - (COINBASE_MATURITY - 1), "hash": node.getblockhash(tip - (COINBASE_MATURITY - 1))})
        processed = w.walletprocesspsbt(res["psbt"])
        assert_equal(processed["complete"], True)
        finalized = node.finalizepsbt(processed["psbt"])
        txid = node.sendrawtransaction(finalized["hex"])
        self.check_annexes(txid, True)
        self.generate(node, 1)
        assert_equal(w.gettransaction(txid)["confirmations"], 1)

        self.log.info("Inputs claiming different hashes for the same referenced height are rejected")
        # Spend more than one coin so that the PSBT has two referencing inputs
        res = w.walletcreatefundedpsbt([], {addr: w.getbalance() - Decimal("0.001")}, 0, {"block_reference": True})
        psbt = PSBT.from_base64(res["psbt"])
        assert len(psbt.i) >= 2
        key = 0x7f
        value = psbt.i[1].map[key]
        psbt.i[1].map[key] = value[:4] + bytes(32)
        conflicting = psbt.to_base64()
        assert_raises_rpc_error(-25, "The transaction cannot be valid", w.walletprocesspsbt, conflicting)
        assert_equal(node.finalizepsbt(conflicting)["complete"], False)
        assert_equal(node.analyzepsbt(conflicting)["error"], "PSBT inputs reference conflicting block hashes for the same height")

        self.log.info("Asking for a block reference without any tr2 input is an error, not a silently replayable transaction")
        node.createwallet("v1")
        v1 = node.get_wallet_rpc("v1")
        miniwallet.send_to(from_node=node, scriptPubKey=address_to_scriptpubkey(v1.getnewaddress(address_type="bech32m")), amount=1_000_000)
        self.generate(node, 1)
        assert_raises_rpc_error(-8, "block_reference requires at least one witness v2 (tr2) input", v1.send, {addr: Decimal("0.001")}, options={"block_reference": True})
        assert_raises_rpc_error(-8, "block_reference requires at least one witness v2 (tr2) input", v1.walletcreatefundedpsbt, [], {addr: Decimal("0.001")}, 0, {"block_reference": True})

        self.log.info("A shallow reorg keeps a referencing transaction; one that replaces the referenced block abandons it")
        node1 = self.nodes[1]
        self.sync_blocks()
        self.disconnect_nodes(0, 1)
        res = w.send({addr: Decimal("0.001")}, options={"block_reference": True})
        self.generate(node, 1, sync_fun=self.no_op)
        self.generate(node1, 2, sync_fun=self.no_op)
        self.connect_nodes(0, 1)
        self.sync_blocks()
        assert res["txid"] in node.getrawmempool()
        assert_equal(w.gettransaction(res["txid"])["details"][0]["abandoned"], False)
        self.generate(node, 1)

        # Bury everything so far, so that the deep reorg below only replaces empty blocks and the new spend
        self.generate(node, COINBASE_MATURITY + 1)
        self.disconnect_nodes(0, 1)
        ref_height = node.getblockcount() - (COINBASE_MATURITY - 1)
        balance_before = w.getbalance()
        res = w.send({addr: Decimal("0.001")}, options={"block_reference": True})
        self.generate(node, 1, sync_fun=self.no_op)
        assert_equal(w.gettransaction(res["txid"])["confirmations"], 1)
        # node1 rebuilds the chain from below the referenced block and outgrows node0
        node1.invalidateblock(node1.getblockhash(ref_height))
        self.generate(node1, node.getblockcount() - node1.getblockcount() + 1, sync_fun=self.no_op)
        self.connect_nodes(0, 1)
        self.sync_blocks()
        assert res["txid"] not in node.getrawmempool()
        tx_info = w.gettransaction(res["txid"])
        assert_equal(tx_info["confirmations"], 0)
        assert_equal(tx_info["details"][0]["abandoned"], True)
        # The abandoned transaction's inputs are spendable again
        assert_equal(w.getbalance(), balance_before)


if __name__ == '__main__':
    WalletBlockReferenceTest(__file__).main()

#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Test gettxproof RPC."""

import json
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet


ZERO_HASH = "00" * 32


class TxProofTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def _check_no_commitment_proof(self, proof):
        coinbase = proof["transactions"][0]
        assert_equal(proof["block_tx_count"], 1)
        assert_equal(len(proof["transactions"]), 1)
        assert_equal(coinbase["pos"], 0)
        assert "wtxid" not in coinbase["proof"]
        assert_equal(coinbase["proof"]["txid"], [])

    def _check_witness_commitment_proof(self, proof, *, expected_target_positions):
        coinbase = proof["transactions"][0]
        targets = proof["transactions"][1:]
        assert_equal(proof["block_tx_count"], 5)
        assert_equal(coinbase["pos"], 0)
        assert "txid" in coinbase["proof"]
        assert "wtxid" not in coinbase["proof"]
        assert_equal([target["pos"] for target in targets], expected_target_positions)
        for target in targets:
            assert "wtxid" in target["proof"]
            assert "txid" not in target["proof"]

    def run_test(self):
        node = self.nodes[0]
        miniwallet = MiniWallet(node)
        vectors_path = Path(__file__).with_name("data") / "rpc_txproof.json"
        genesis_hash = node.getblockhash(0)

        node.setmocktime(node.getblockheader(genesis_hash)["time"])
        self.generatetodescriptor(node, 200, miniwallet.get_descriptor())
        miniwallet.rescan_utxos()

        self.log.info("Check a no-witness-commitment proof against the JSON vector")
        genesis_wtxid = node.getblock(genesis_hash)["tx"][0]
        no_commitment_proof = node.gettxproof([genesis_wtxid], genesis_hash)
        self._check_no_commitment_proof(no_commitment_proof)

        self.log.info("Check a witness-commitment proof against the JSON vector")
        tx_chain = miniwallet.send_self_transfer_chain(from_node=node, chain_length=4)
        assert_raises_rpc_error(-5, "Not all transactions found in specified block", node.gettxproof, [tx_chain[-1]["wtxid"]], genesis_hash)
        blockhash = self.generate(node, 1)[0]
        witness_proof = node.gettxproof([tx_chain[-1]["wtxid"]], blockhash)
        self._check_witness_commitment_proof(witness_proof, expected_target_positions=[4])

        self.log.info("Check a coinbase-only proof")
        coinbase_wtxid = witness_proof["transactions"][0]["wtxid"]
        coinbase_only_proof = {
            **witness_proof,
            "transactions": [witness_proof["transactions"][0]],
        }
        assert_equal(node.gettxproof([], blockhash), coinbase_only_proof)
        assert_equal(node.gettxproof([coinbase_wtxid], blockhash), coinbase_only_proof)

        with vectors_path.open(encoding="utf8") as f:
            vectors = json.load(f)
        assert_equal(vectors, {
            "no_witness_commitment": no_commitment_proof,
            "witness_commitment": witness_proof,
        })

        self.log.info("Check invalid lookup arguments")
        assert_raises_rpc_error(-8, "blockhash must be of length 64", node.gettxproof, [tx_chain[-1]["wtxid"]], "00000000")
        assert_raises_rpc_error(-8, "wtxids[0] must be of length 64", node.gettxproof, ["00000000"], blockhash)
        assert_raises_rpc_error(-8, "Invalid parameter, duplicated wtxid", node.gettxproof, [tx_chain[-1]["wtxid"], tx_chain[-1]["wtxid"]], blockhash)
        assert_raises_rpc_error(-8, "Parameter 'wtxids' accepts at most one element", node.gettxproof, [tx_chain[-2]["wtxid"], tx_chain[-1]["wtxid"]], blockhash)
        assert_raises_rpc_error(-5, "Block not found", node.gettxproof, [tx_chain[-1]["wtxid"]], ZERO_HASH)


if __name__ == "__main__":
    TxProofTest(__file__).main()

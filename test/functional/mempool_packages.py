#!/usr/bin/env python3
# Copyright (c) 2014-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test descendant package tracking code."""

from decimal import Decimal

from test_framework.messages import (
    DEFAULT_DESCENDANT_LIMIT,
)
from test_framework.p2p import P2PTxInvStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet

# custom limits for node1
CUSTOM_DESCENDANT_LIMIT = 10

class MempoolPackagesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [
            [
                "-maxorphantx=1000",
                "-whitelist=noban@127.0.0.1",  # immediate tx relay
            ],
            [
                "-maxorphantx=1000",
                "-limitdescendantcount={}".format(CUSTOM_DESCENDANT_LIMIT),
                "-limitclustercount={}".format(CUSTOM_DESCENDANT_LIMIT),
            ],
        ]

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.wallet.rescan_utxos()

        peer_inv_store = self.nodes[0].add_p2p_connection(P2PTxInvStore()) # keep track of invs

        # Now test descendant chain limits
        tx_children = []
        # First create one parent tx with 10 children
        tx_with_children = self.wallet.send_self_transfer_multi(from_node=self.nodes[0], num_outputs=10)
        parent_transaction = tx_with_children["txid"]
        transaction_package = tx_with_children["new_utxos"]

        # Sign and send up to MAX_DESCENDANT transactions chained off the parent tx
        chain = [] # save sent txs for the purpose of checking node1's mempool later (see below)
        for _ in range(DEFAULT_DESCENDANT_LIMIT - 1):
            utxo = transaction_package.pop(0)
            new_tx = self.wallet.send_self_transfer_multi(from_node=self.nodes[0], num_outputs=10, utxos_to_spend=[utxo])
            txid = new_tx["txid"]
            chain.append(txid)
            if utxo['txid'] is parent_transaction:
                tx_children.append(txid)
            transaction_package.extend(new_tx["new_utxos"])

        mempool = self.nodes[0].getrawmempool(True)
        assert_equal(mempool[parent_transaction]['descendantcount'], DEFAULT_DESCENDANT_LIMIT)
        assert_equal(sorted(mempool[parent_transaction]['spentby']), sorted(tx_children))

        for child in tx_children:
            assert_equal(mempool[child]['depends'], [parent_transaction])

        # Check that node1's mempool is as expected, containing:
        # - parent tx for descendant test
        # - txs chained off parent tx (-> custom descendant limit)
        self.wait_until(lambda: len(self.nodes[1].getrawmempool()) == CUSTOM_DESCENDANT_LIMIT, timeout=10)
        mempool0 = self.nodes[0].getrawmempool(False)
        mempool1 = self.nodes[1].getrawmempool(False)
        assert set(mempool1).issubset(set(mempool0))
        assert parent_transaction in mempool1
        for tx in chain:
            if tx in mempool1:
                entry = self.nodes[1].getmempoolentry(tx)
                assert entry["descendantcount"] <= CUSTOM_DESCENDANT_LIMIT
        # TODO: more detailed check of node1's mempool (fees etc.)

        # TODO: test descendant size limits

        # Test reorg handling
        # First, the basics:
        self.generate(self.nodes[0], 1)
        self.nodes[1].invalidateblock(self.nodes[0].getbestblockhash())
        self.nodes[1].reconsiderblock(self.nodes[0].getbestblockhash())

        # Now test the case where node1 has a transaction T in its mempool that
        # depends on transactions A and B which are in a mined block, and the
        # block containing A and B is disconnected, AND B is not accepted back
        # into node1's mempool because its ancestor count is too high.

        # Create 8 transactions, like so:
        # Tx0 -> Tx1 (vout0)
        #   \--> Tx2 (vout1) -> Tx3 -> Tx4 -> Tx5 -> Tx6 -> Tx7
        #
        # Mine them in the next block, then generate a new tx8 that spends
        # Tx1 and Tx7, and add to node1's mempool, then disconnect the
        # last block.

        # Create tx0 with 2 outputs
        tx0 = self.wallet.send_self_transfer_multi(from_node=self.nodes[0], num_outputs=2)

        # Create tx1
        tx1 = self.wallet.send_self_transfer(from_node=self.nodes[0], utxo_to_spend=tx0["new_utxos"][0])

        # Create tx2-7
        tx7 = self.wallet.send_self_transfer_chain(from_node=self.nodes[0], utxo_to_spend=tx0["new_utxos"][1], chain_length=6)[-1]

        # Mine these in a block
        self.generate(self.nodes[0], 1)

        # Now generate tx8, with a big fee
        self.wallet.send_self_transfer_multi(from_node=self.nodes[0], utxos_to_spend=[tx1["new_utxo"], tx7["new_utxo"]], fee_per_output=40000)
        self.sync_mempools()

        # Now try to disconnect the tip on each node...
        self.nodes[1].invalidateblock(self.nodes[1].getbestblockhash())
        self.nodes[0].invalidateblock(self.nodes[0].getbestblockhash())
        self.sync_blocks()

if __name__ == '__main__':
    MempoolPackagesTest().main()

#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that fast rescan using block filters for descriptor wallets detects
   top-ups correctly and finds the same transactions than the slow variant."""
import os
from typing import List

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


KEYPOOL_SIZE = 3     # smaller than default size to check topup
NUM_BLOCKS = 20      # number of blocks to mine


class WalletFastRescanTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[f'-keypool={KEYPOOL_SIZE}', '-blockfilterindex=1']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def get_wallet_txids(self, node: TestNode, wallet_name: str) -> List[str]:
        w = node.get_wallet_rpc(wallet_name)
        txs = w.listtransactions('*', 1000000)
        return [tx['txid'] for tx in txs]

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        wallet.rescan_utxos()

        self.log.info("Create descriptor wallet with backup")
        WALLET_BACKUP_FILENAME = os.path.join(node.datadir, 'wallet.bak')
        node.createwallet(wallet_name='topup_test', descriptors=True)
        w = node.get_wallet_rpc('topup_test')
        # This test assumes four output types, receive and change
        assert_equal(len(w.listdescriptors()['descriptors']), 4 * 2)
        w.backupwallet(WALLET_BACKUP_FILENAME)

        self.log.info(f"Create txs sending to end range address of each descriptor, triggering top-ups")
        for i in range(NUM_BLOCKS):
            self.log.info(f"Block {i+1}/{NUM_BLOCKS}")
            for addr_type in ["legacy", "p2sh-segwit", "bech32", "bech32m"]:
                addr = w.getnewaddress(address_type=addr_type)
                info = w.getaddressinfo(addr)
                desc_info = next((desc for desc in w.listdescriptors()['descriptors'] if desc['desc'] == info["parent_desc"]), None)
                start_range, end_range = desc_info['range']
                self.log.info(f"-> range [{start_range},{end_range}], last address {addr}")
                wallet.send_to(from_node=node, scriptPubKey=bytes.fromhex(info["scriptPubKey"]), amount=10000)
            self.generate(node, 1)

        self.log.info("Import wallet backup with block filter index")
        with node.assert_debug_log(['fast variant using block filters']):
            node.restorewallet('rescan_fast', WALLET_BACKUP_FILENAME)
        txids_fast = self.get_wallet_txids(node, 'rescan_fast')

        self.restart_node(0, [f'-keypool={KEYPOOL_SIZE}', '-blockfilterindex=0'])
        self.log.info("Import wallet backup w/o block filter index")
        with node.assert_debug_log(['slow variant inspecting all blocks']):
            node.restorewallet("rescan_slow", WALLET_BACKUP_FILENAME)
        txids_slow = self.get_wallet_txids(node, 'rescan_slow')

        assert_equal(len(txids_slow), 4 * NUM_BLOCKS)
        assert_equal(len(txids_fast), 4 * NUM_BLOCKS)
        assert_equal(sorted(txids_slow), sorted(txids_fast))


if __name__ == '__main__':
    WalletFastRescanTest().main()

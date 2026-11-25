#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the contrib/wallet-tools/import-pruned.py tool.

A wallet on a pruned node is funded, its funding blocks are pruned, and the
descriptors are imported into a fresh wallet without a rescan. The tool then
restores the coins from the UTXO set, fetching the pruned blocks from the
unpruned peer.
"""

import os.path
import shlex
import subprocess
import sys
import time

from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

# The test framework defaults to a keypool of 1; use something a bit larger
# so that gaps between used indexes behave as in a normal wallet.
KEYPOOL = 10


class ImportPrunedTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [
            [],
            ["-fastprune", "-prune=1", f"-keypool={KEYPOOL}"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_cli()
        self.skip_if_no_wallet()

    def setup_network(self):
        # The pruned node is connected only after the old blocks are mined,
        # so that the miner can use a mocked clock without the peer
        # connection timing out.
        self.setup_nodes()

    def run_tool(self, node, wallet, *args, expected_code=0):
        tool = os.path.join(self.config["environment"]["SRCDIR"], "contrib", "wallet-tools", "import-pruned.py")
        rpc_argv = node.binaries.rpc_argv() + [f"-datadir={node.datadir_path}"]
        cmd = [sys.executable, tool, f"--cli={shlex.join(rpc_argv)}", f"--wallet={wallet}", "--utxo", *args]
        res = subprocess.run(cmd, text=True, capture_output=True)
        self.log.debug(res.stderr)
        assert_equal(res.returncode, expected_code)
        return res

    def run_test(self):
        miner, pruned = self.nodes
        pruned.createwallet("w1")
        w1 = pruned.get_wallet_rpc("w1")
        miner.createwallet("miner")
        miner_wallet = miner.get_wallet_rpc("miner")

        self.log.info("Fund the wallet in blocks that will be pruned")
        # Backdate these blocks so that a later import with timestamp "now"
        # does not try to rescan them.
        miner.setmocktime(int(time.time()) - 3 * 60 * 60)
        self.generatetoaddress(miner, 101, miner_wallet.getnewaddress(), sync_fun=self.no_op)
        receive_desc = next(d["desc"] for d in w1.listdescriptors()["descriptors"]
                            if d["desc"].startswith("wpkh(") and not d["internal"])
        targets = {
            w1.getnewaddress(address_type="bech32"): Decimal("1.0"),
            w1.getnewaddress(address_type="bech32m"): Decimal("2.0"),
            w1.getrawchangeaddress(address_type="bech32"): Decimal("0.5"),
            # Far along the receive chain, to exercise keypool top-up order
            miner.deriveaddresses(receive_desc, [5, 5])[0]: Decimal("0.25"),
            # Beyond the fresh wallet's initial keypool; only found with lookahead
            # and only recognized once index 5 has extended the keypool
            miner.deriveaddresses(receive_desc, [KEYPOOL + 4] * 2)[0]: Decimal("0.125"),
        }
        for address, amount in targets.items():
            miner_wallet.sendtoaddress(address, amount)
            self.generate(miner, 1, sync_fun=self.no_op)
        funding_blocks = [miner.getblockhash(h) for h in range(102, 102 + len(targets))]
        self.generate(miner, 500, sync_fun=self.no_op)
        miner.setmocktime(0)
        self.generate(miner, 300, sync_fun=self.no_op)

        self.log.info("Sync and prune")
        self.connect_nodes(1, 0)
        self.sync_blocks()
        assert pruned.pruneblockchain(600) >= 102 + len(targets)
        for blockhash in funding_blocks:
            assert_raises_rpc_error(-1, "Block not available (pruned data)", pruned.getblock, blockhash)
        total = sum(targets.values())
        # w1 was online and topped up its keypool as the coins arrived
        assert_equal(w1.getbalance(), total)

        self.log.info("Import the descriptors into a fresh wallet without rescan")
        pruned.createwallet(wallet_name="w2", blank=True)
        w2 = pruned.get_wallet_rpc("w2")
        requests = [{"desc": d["desc"], "timestamp": "now", "active": d["active"], "internal": d["internal"]}
                    for d in w1.listdescriptors(private=True)["descriptors"]]
        assert all(r["success"] for r in w2.importdescriptors(requests))
        assert_equal(w2.getbalance(), 0)

        self.log.info("Dry run lists the outputs without importing")
        res = self.run_tool(pruned, "w2", "--dry-run")
        assert_equal(len(res.stdout.splitlines()), len(targets))
        assert_equal(w2.getbalance(), 0)
        assert_equal(pruned.getpeerinfo()[0]["id"], 0)  # no block was fetched

        self.log.info("Without lookahead the output beyond the keypool is missed, and the tool says so")
        res = self.run_tool(pruned, "w2", "--lookahead=0")
        assert_equal(w2.getbalance(), total - Decimal("0.125"))
        assert "rerun to pick up" in res.stderr
        assert "Fetched block" in res.stderr
        for blockhash in funding_blocks[:-1]:
            pruned.getblock(blockhash)  # fetched from the peer

        self.log.info("A rerun picks up the remaining output and skips known transactions")
        res = self.run_tool(pruned, "w2")
        assert_equal(w2.getbalance(), total)
        assert "Skipping" in res.stderr
        assert "rerun to pick up" not in res.stderr
        assert_equal(len(w2.listunspent()), len(targets))
        assert_equal({u["address"] for u in w2.listunspent()}, set(targets))

        self.log.info("Running again changes nothing")
        res = self.run_tool(pruned, "w2")
        assert "Imported" not in res.stderr
        assert_equal(w2.getbalance(), total)

        self.log.info("A mode is required")
        tool = os.path.join(self.config["environment"]["SRCDIR"], "contrib", "wallet-tools", "import-pruned.py")
        assert_equal(subprocess.run([sys.executable, tool], capture_output=True).returncode, 2)


if __name__ == "__main__":
    ImportPrunedTest(__file__).main()

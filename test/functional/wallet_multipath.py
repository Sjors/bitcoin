#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test wallets that store their descriptors in multipath form."""

import os.path

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)
from test_framework.wallet_util import WalletUnlock


class WalletMultipathTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [['-keypool=100']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def create_multipath_wallet(self, name, blank=False, disable_private_keys=False):
        self.nodes[0].createwallet(wallet_name=name, blank=blank, disable_private_keys=disable_private_keys, multipath=True)
        return self.nodes[0].get_wallet_rpc(name)

    def test_creation(self):
        self.log.info("Test multipath wallet creation")
        wallet = self.create_multipath_wallet("mp")

        assert "multipath_descriptors" in wallet.getwalletinfo()["flags"]

        # One active multipath descriptor per output type, covering both chains
        descriptors = wallet.listdescriptors()["descriptors"]
        assert_equal(len(descriptors), 4)
        for item in descriptors:
            assert "/<0;1>/*" in item["desc"]
            assert_equal(item["active"], True)
            assert "internal" not in item
            assert_equal(item["next_index"], 0)

        # Both chains have their own keypool of equal size
        info = wallet.getwalletinfo()
        assert_equal(info["keypoolsize"], 400)
        assert_equal(info["keypoolsize_hd_internal"], 400)

        # The private descriptors are also multipath
        for item in wallet.listdescriptors(True)["descriptors"]:
            assert "/<0;1>/*" in item["desc"]
            assert "tprv" in item["desc"]

    def test_addresses(self):
        self.log.info("Test receive and change addresses come from the same descriptor")
        wallet = self.nodes[0].get_wallet_rpc("mp")

        addr = wallet.getnewaddress(address_type="bech32")
        change = wallet.getrawchangeaddress(address_type="bech32")
        addr_info = wallet.getaddressinfo(addr)
        change_info = wallet.getaddressinfo(change)
        assert "/<0;1>/*" in addr_info["parent_desc"]
        assert_equal(addr_info["parent_desc"], change_info["parent_desc"])
        assert addr_info["hdkeypath"].endswith("/0/0")
        assert change_info["hdkeypath"].endswith("/1/0")

        # The next indexes advance independently per chain
        wallet.getnewaddress(address_type="bech32")
        wpkh_desc = next(d for d in wallet.listdescriptors()["descriptors"] if d["desc"].startswith("wpkh("))
        assert_equal(wpkh_desc["next_index"], 2)

    def test_spending(self):
        self.log.info("Test funding, spending, and change detection")
        node = self.nodes[0]
        wallet = node.get_wallet_rpc("mp")

        addr = wallet.getnewaddress()
        self.generatetoaddress(node, COINBASE_MATURITY + 1, addr)
        assert_greater_than(wallet.getbalance(), 0)

        node.createwallet(wallet_name="other")
        other = node.get_wallet_rpc("other")
        txid = wallet.sendtoaddress(other.getnewaddress(), 1)
        self.generate(node, 1)
        assert_equal(other.getbalance(), 1)

        # The change output pays back to the wallet's internal chain
        change_outputs = [d for d in wallet.gettransaction(txid, verbose=True)["decoded"]["vout"]
                          if wallet.getaddressinfo(d["scriptPubKey"]["address"])["ismine"]]
        assert_equal(len(change_outputs), 1)
        change_info = wallet.getaddressinfo(change_outputs[0]["scriptPubKey"]["address"])
        assert_equal(change_info["ischange"], True)
        assert "/<0;1>/*" in change_info["parent_desc"]

    def test_reload(self):
        self.log.info("Test unloading and reloading a multipath wallet")
        node = self.nodes[0]
        wallet = node.get_wallet_rpc("mp")
        balance = wallet.getbalance()
        descriptors = wallet.listdescriptors()["descriptors"]

        wallet.unloadwallet()
        node.loadwallet("mp")
        assert_equal(wallet.getbalance(), balance)
        assert_equal(wallet.listdescriptors()["descriptors"], descriptors)

    def test_encryption(self):
        self.log.info("Test encrypting a multipath wallet")
        node = self.nodes[0]
        wallet = node.get_wallet_rpc("mp")
        other = node.get_wallet_rpc("other")

        wallet.encryptwallet("pass")
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase", wallet.sendtoaddress, other.getnewaddress(), 1)
        with WalletUnlock(wallet, "pass"):
            wallet.sendtoaddress(other.getnewaddress(), 1)
        self.generate(node, 1)
        assert_equal(other.getbalance(), 2)

    def test_backup_restore(self):
        self.log.info("Test backing up and restoring a multipath wallet")
        node = self.nodes[0]
        wallet = node.get_wallet_rpc("mp")
        balance = wallet.getbalance()

        backup_path = os.path.join(self.nodes[0].datadir_path, "mp.bak")
        wallet.backupwallet(backup_path)
        node.restorewallet("mp_restored", backup_path)
        restored = node.get_wallet_rpc("mp_restored")
        assert "multipath_descriptors" in restored.getwalletinfo()["flags"]
        assert_equal(restored.getbalance(), balance)
        restored.unloadwallet()

    def run_test(self):
        self.test_creation()
        self.test_addresses()
        self.test_spending()
        self.test_reload()
        self.test_encryption()
        self.test_backup_restore()
if __name__ == '__main__':
    WalletMultipathTest(__file__).main()

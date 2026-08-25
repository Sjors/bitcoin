#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test wallets that store their descriptors in multipath form."""

import os.path

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.descriptors import descsum_create
from test_framework.extendedkey import ExtendedPrivateKey
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
            assert_equal(item["next_index_internal"], 0)

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
        assert_equal(wpkh_desc["next_index_internal"], 1)

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

    def test_import_roundtrip(self):
        self.log.info("Test importing exported multipath descriptors into a fresh multipath wallet")
        node = self.nodes[0]

        # An unused wallet's descriptors hand out identical addresses after a round trip
        source = self.create_multipath_wallet("mp_source")
        imported = self.create_multipath_wallet("mp_source_imported", blank=True)
        result = imported.importdescriptors([{
            "desc": item["desc"],
            "timestamp": "now",
            "active": True,
        } for item in source.listdescriptors(True)["descriptors"]])
        assert all(r["success"] for r in result)
        assert_equal(sorted(d["desc"] for d in imported.listdescriptors()["descriptors"]),
                     sorted(d["desc"] for d in source.listdescriptors()["descriptors"]))
        for address_type in ("legacy", "p2sh-segwit", "bech32", "bech32m"):
            assert_equal(imported.getnewaddress(address_type=address_type),
                         source.getnewaddress(address_type=address_type))
            assert_equal(imported.getrawchangeaddress(address_type=address_type),
                         source.getrawchangeaddress(address_type=address_type))
        source.unloadwallet()
        imported.unloadwallet()

        # A used wallet's funds, on both chains, are found by a rescan
        wallet = node.get_wallet_rpc("mp")
        with WalletUnlock(wallet, "pass"):
            private_descriptors = wallet.listdescriptors(True)["descriptors"]
        rescanned = self.create_multipath_wallet("mp_imported", blank=True)
        result = rescanned.importdescriptors([{
            "desc": item["desc"],
            "timestamp": 0,
            "active": True,
        } for item in private_descriptors])
        assert all(r["success"] for r in result)
        assert_equal(rescanned.getbalance(), wallet.getbalance())
        rescanned.unloadwallet()

    def test_import_rejections(self):
        self.log.info("Test that a multipath wallet rejects unsupported imports")
        wallet = self.create_multipath_wallet("mp_strict", blank=True, disable_private_keys=True)
        source = self.nodes[0].get_wallet_rpc("mp")
        multipath_desc = next(d["desc"] for d in source.listdescriptors()["descriptors"] if d["desc"].startswith("wpkh("))

        def import_desc(desc, **kwargs):
            return wallet.importdescriptors([{"desc": desc, "timestamp": 0, **kwargs}])[0]

        # Only multipath descriptors with exactly two paths are supported
        single_path = descsum_create(multipath_desc.split("#")[0].replace("/<0;1>/", "/0/"))
        result = import_desc(single_path)
        assert_equal(result["success"], False)
        assert "only supports multipath descriptors with exactly two derivation paths" in result["error"]["message"]

        three_paths = descsum_create(multipath_desc.split("#")[0].replace("/<0;1>/", "/<0;1;2>/"))
        result = import_desc(three_paths)
        assert_equal(result["success"], False)
        assert "only supports multipath descriptors with exactly two derivation paths" in result["error"]["message"]

        # The internal option cannot be combined with a multipath descriptor
        result = import_desc(multipath_desc, internal=True)
        assert_equal(result["success"], False)
        assert "Cannot have multipath descriptor while also specifying 'internal'" in result["error"]["message"]

        # A valid multipath descriptor imports fine
        result = import_desc(multipath_desc, active=True)
        assert_equal(result["success"], True)
        assert_equal(len(wallet.listdescriptors()["descriptors"]), 1)
        wallet.unloadwallet()

    def test_hardened_multipath(self):
        self.log.info("Test that hardened multipath specifiers are rejected")
        wallet = self.create_multipath_wallet("mp_hardened", blank=True)
        xprv = ExtendedPrivateKey.generate().to_string()
        hardened_desc = descsum_create(f"wpkh({xprv}/84h/1h/0h/<0h;1h>/*)")
        result = wallet.importdescriptors([{"desc": hardened_desc, "timestamp": 0}])[0]
        assert_equal(result["success"], False)
        assert "Multipath specifiers with hardened derivation are not supported" in result["error"]["message"]
        wallet.unloadwallet()

    def test_createwalletdescriptor(self):
        self.log.info("Test createwalletdescriptor on a multipath wallet")
        wallet = self.create_multipath_wallet("mp_manual", blank=True)
        hdkey = wallet.addhdkey()["xpub"]

        assert_raises_rpc_error(-8, "Cannot specify 'internal' for a multipath descriptors wallet",
                                wallet.createwalletdescriptor, type="bech32m", internal=True, hdkey=hdkey)

        result = wallet.createwalletdescriptor(type="bech32m", hdkey=hdkey)
        assert_equal(len(result["descs"]), 1)
        assert "/<0;1>/*" in result["descs"][0]

        # The wallet has the new multipath descriptor plus the single path
        # unused() container holding the HD key
        descriptors = wallet.listdescriptors()["descriptors"]
        assert_equal(len(descriptors), 2)
        multipath_descs = [d for d in descriptors if "/<0;1>/*" in d["desc"]]
        assert_equal(len(multipath_descs), 1)
        assert_equal(multipath_descs[0]["active"], True)
        assert "internal" not in multipath_descs[0]
        # Both chains can produce addresses
        wallet.getnewaddress(address_type="bech32m")
        wallet.getrawchangeaddress(address_type="bech32m")

        # The mix of a multipath descriptor and an unused() key container survives a reload
        wallet.unloadwallet()
        self.nodes[0].loadwallet("mp_manual")
        assert_equal(len(wallet.listdescriptors()["descriptors"]), 2)
        wallet.unloadwallet()

    def test_watchonly_export(self):
        self.log.info("Test exportwatchonlywallet for a multipath wallet")
        node = self.nodes[0]
        wallet = node.get_wallet_rpc("mp")

        export_path = os.path.join(self.nodes[0].datadir_path, "mp_watchonly.dat")
        wallet.exportwatchonlywallet(export_path)
        node.restorewallet("mp_watch", export_path)
        watch = node.get_wallet_rpc("mp_watch")

        info = watch.getwalletinfo()
        assert "multipath_descriptors" in info["flags"]
        assert_equal(info["private_keys_enabled"], False)
        assert_equal(watch.getbalances()["mine"]["trusted"], wallet.getbalance())

        # The watchonly wallet hands out the same receive and change addresses
        assert_equal(watch.getnewaddress(address_type="bech32"), wallet.getnewaddress(address_type="bech32"))
        assert_equal(watch.getrawchangeaddress(address_type="bech32"), wallet.getrawchangeaddress(address_type="bech32"))

        # And can produce a PSBT that the full wallet signs
        psbt = watch.walletcreatefundedpsbt([], [{wallet.getnewaddress(): 1}])["psbt"]
        with WalletUnlock(wallet, "pass"):
            signed = wallet.walletprocesspsbt(psbt)
        assert_equal(signed["complete"], True)
        node.sendrawtransaction(signed["hex"])
        self.generate(node, 1)
        watch.unloadwallet()

    def run_test(self):
        self.test_creation()
        self.test_addresses()
        self.test_spending()
        self.test_reload()
        self.test_encryption()
        self.test_backup_restore()
        self.test_import_roundtrip()
        self.test_import_rejections()
        self.test_hardened_multipath()
        self.test_createwalletdescriptor()
        self.test_watchonly_export()


if __name__ == '__main__':
    WalletMultipathTest(__file__).main()

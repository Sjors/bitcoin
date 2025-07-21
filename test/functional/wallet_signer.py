#!/usr/bin/env python3
# Copyright (c) 2017-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test external signer.

Verify that a bitcoind node can use an external signer command
See also rpc_signer.py for tests without wallet context.
"""
import os

from test_framework.descriptors import descsum_create
from test_framework.extendedkey import ExtendedPrivateKey
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)


class WalletSignerTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3

        self.extra_args = [
            [],
            [f"-signer={self.mock_signer_path()}", '-keypool=10'],
            # Node for the signer mock's wallet, kept offline so the mock
            # can't cheat by e.g. inspecting the UTXO set
            ["-maxconnections=0"],
        ]

    def setup_network(self):
        self.setup_nodes()
        # Leave the signer mock's node disconnected
        self.connect_nodes(0, 1)

    def sync_except_mock(self):
        """Sync all nodes except the signer mock's, which never receives blocks."""
        self.sync_all(self.nodes[0:2])

    def skip_test_if_missing_module(self):
        self.skip_if_no_external_signer()
        self.skip_if_no_wallet()

    def set_mock_result(self, node, res):
        with open(os.path.join(node.cwd, "mock_result"), "w") as f:
            f.write(res)

    def clear_mock_result(self, node):
        os.remove(os.path.join(node.cwd, "mock_result"))

    def set_mock_sign_mode(self, node, mode):
        with open(os.path.join(node.cwd, "mock_sign_mode"), "w") as f:
            f.write(mode)

    def clear_mock_sign_mode(self, node):
        os.remove(os.path.join(node.cwd, "mock_sign_mode"))

    def init_mock_node(self):
        """Hand the signer mock its dedicated offline node, on which it
        creates the wallet it signs with."""
        signer_node = self.nodes[2]
        assert_equal(signer_node.getconnectioncount(), 0)
        with open(os.path.join(self.nodes[1].cwd, "mock_rpc_url"), "w") as f:
            f.write(signer_node.url)

    def run_test(self):
        self.init_mock_node()
        self.test_valid_signer()
        self.test_import_descriptor()
        self.test_hot_key()
        self.test_unusual_signer()
        self.test_misbehaving_signer()
        self.test_disconnected_signer()
        self.restart_node(1, [f"-signer={self.mock_signer_path('invalid_signer.py')}", "-keypool=10"])
        self.test_invalid_signer()
        self.restart_node(1, [f"-signer={self.mock_signer_path('multi_signers.py')}", "-keypool=10"])
        self.test_multiple_signers()
        self.restart_node(1)
        self.test_descriptor_registration()

    def test_valid_signer(self):
        self.log.debug(f"-signer={self.mock_signer_path()}")

        # Create new wallets for an external signer.
        self.nodes[1].createwallet(wallet_name='hww', external_signer=True)
        hww = self.nodes[1].get_wallet_rpc('hww')
        assert_equal(hww.getwalletinfo()["external_signer"], True)

        # Private keys are disabled by default
        assert_equal(hww.getwalletinfo()["private_keys_enabled"], False)

        # Private keys can be explicitly enabled for external signer wallets
        self.nodes[1].createwallet(wallet_name='hww_hot', external_signer=True, disable_private_keys=False)
        hww_hot = self.nodes[1].get_wallet_rpc('hww_hot')
        assert_equal(hww_hot.getwalletinfo()["external_signer"], True)
        assert_equal(hww_hot.getwalletinfo()["private_keys_enabled"], True)
        self.nodes[1].unloadwallet('hww_hot')

        # A blank external signer wallet does not auto-import any keys.
        self.nodes[1].createwallet(wallet_name='hww_blank', external_signer=True, blank=True)
        hww_blank = self.nodes[1].get_wallet_rpc('hww_blank')
        assert_equal(hww_blank.getwalletinfo()["keypoolsize"], 0)
        assert_equal(hww_blank.listdescriptors()["descriptors"], [])
        self.nodes[1].unloadwallet('hww_blank')

        # Flag can be set afterwards
        self.nodes[1].createwallet(wallet_name='not_hww_initially', external_signer=False)
        not_hww_initially = self.nodes[1].get_wallet_rpc('not_hww_initially')
        assert_equal(not_hww_initially.getwalletinfo()["external_signer"], False)
        # Without external_signer, private keys are enabled by default
        assert_equal(not_hww_initially.getwalletinfo()["private_keys_enabled"], True)
        not_hww_initially.setwalletflag("external_signer", True)
        assert_equal(not_hww_initially.getwalletinfo()["external_signer"], True)

        self.set_mock_result(self.nodes[1], '0 {"invalid json"}')
        assert_raises_rpc_error(-1, 'Unable to parse JSON',
            self.nodes[1].createwallet, wallet_name='hww2', external_signer=True
        )
        self.clear_mock_result(self.nodes[1])

        assert_equal(hww.getwalletinfo()["keypoolsize"], 40)

        address1 = hww.getnewaddress(address_type="bech32")
        assert_equal(address1, "bcrt1qm90ugl4d48jv8n6e5t9ln6t9zlpm5th68x4f8g")
        address_info = hww.getaddressinfo(address1)
        assert_equal(address_info['solvable'], True)
        assert_equal(address_info['ismine'], True)
        assert_equal(address_info['hdkeypath'], "m/84h/1h/0h/0/0")

        address2 = hww.getnewaddress(address_type="p2sh-segwit")
        assert_equal(address2, "2N2gQKzjUe47gM8p1JZxaAkTcoHPXV6YyVp")
        address_info = hww.getaddressinfo(address2)
        assert_equal(address_info['solvable'], True)
        assert_equal(address_info['ismine'], True)
        assert_equal(address_info['hdkeypath'], "m/49h/1h/0h/0/0")

        address3 = hww.getnewaddress(address_type="legacy")
        assert_equal(address3, "n1LKejAadN6hg2FrBXoU1KrwX4uK16mco9")
        address_info = hww.getaddressinfo(address3)
        assert_equal(address_info['solvable'], True)
        assert_equal(address_info['ismine'], True)
        assert_equal(address_info['hdkeypath'], "m/44h/1h/0h/0/0")

        address4 = hww.getnewaddress(address_type="bech32m")
        assert_equal(address4, "bcrt1phw4cgpt6cd30kz9k4wkpwm872cdvhss29jga2xpmftelhqll62ms4e9sqj")
        address_info = hww.getaddressinfo(address4)
        assert_equal(address_info['solvable'], True)
        assert_equal(address_info['ismine'], True)
        assert_equal(address_info['hdkeypath'], "m/86h/1h/0h/0/0")

        hww.setwalletflag("external_signer", False)
        assert_raises_rpc_error(-1, "There is no ScriptPubKeyManager for this address", hww.walletdisplayaddress, address1)
        hww.setwalletflag("external_signer", True)

        self.log.info('Test walletdisplayaddress')
        for address in [address1, address2, address3]:
            result = hww.walletdisplayaddress(address)
            assert_equal(result, {"address": address})

        assert_raises_rpc_error(
            -4,
            "Error: sendtoaddress and sendmany are not supported for wallets with external signers; use send instead",
            hww.sendtoaddress,
            self.nodes[0].getnewaddress(),
            0.01,
        )
        assert_raises_rpc_error(
            -4,
            "Error: sendtoaddress and sendmany are not supported for wallets with external signers; use send instead",
            hww.sendmany,
            "",
            {self.nodes[0].getnewaddress(): 0.01},
        )

        # Handle error thrown by script
        self.set_mock_result(self.nodes[1], "2")
        assert_raises_rpc_error(-1, 'RunCommandParseJSON error',
            hww.walletdisplayaddress, address1
        )
        self.clear_mock_result(self.nodes[1])

        # Returned address MUST match:
        address_fail = hww.getnewaddress(address_type="bech32")
        assert_equal(address_fail, "bcrt1ql7zg7ukh3dwr25ex2zn9jse926f27xy2jz58tm")
        assert_raises_rpc_error(-1, 'Signer echoed unexpected address wrong_address',
            hww.walletdisplayaddress, address_fail
        )

        self.log.info('Fund hww wallet')
        for address in [address1, address2, address3, address4]:
            self.nodes[0].sendtoaddress(address, 1)
        self.generate(self.nodes[0], 1, sync_fun=self.sync_except_mock)
        assert_equal(hww.getwalletinfo()["txcount"], 4)

        dest = self.nodes[0].getnewaddress(address_type='bech32')

        self.log.info('Test send using hww1')

        # Spend all four address types at once. Don't broadcast the transaction
        # yet so the RPC returns the raw hex.
        res = hww.send(outputs={dest:3.5}, add_to_wallet=False)
        assert res["complete"]
        assert_equal(len(hww.decoderawtransaction(res["hex"])["vin"]), 4)
        assert hww.testmempoolaccept([res["hex"]])[0]["allowed"]

        self.log.info('Test sendall using hww1')

        res = hww.sendall(recipients=[{dest:3.5}, hww.getrawchangeaddress()], add_to_wallet=False)
        assert res["complete"]
        assert hww.testmempoolaccept([res["hex"]])[0]["allowed"]
        # Broadcast transaction so we can bump the fee
        hww.sendrawtransaction(res["hex"])

        self.log.info('Test bumpfee using hww1')

        orig_tx_id = res["txid"]
        res = hww.bumpfee(orig_tx_id)
        assert_greater_than(res["fee"], res["origfee"])
        assert_equal(res["errors"], [])

    def test_import_descriptor(self):
        self.log.info('Test using the signer for an imported descriptor, without reloading')

        self.nodes[1].createwallet(wallet_name='hww_import', external_signer=True, blank=True)
        hww_import = self.nodes[1].get_wallet_rpc('hww_import')
        xpub = "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B"
        result = hww_import.importdescriptors([{
            "desc": descsum_create(f"wpkh([00000001/84h/1h/0h]{xpub}/0/*)"),
            "active": True,
            "timestamp": "now",
        }])
        assert_equal(result[0]["success"], True)

        address = hww_import.getnewaddress(address_type="bech32")
        display_path = os.path.join(self.nodes[1].cwd, "mock_displayaddress")
        with open(display_path, "w") as f:
            f.write(address)
        assert_equal(hww_import.walletdisplayaddress(address), {"address": address})
        os.remove(display_path)
        self.nodes[1].unloadwallet('hww_import')

    def test_hot_key(self):
        self.log.info('Test spending a hot key coin in an external signer wallet')

        self.nodes[1].createwallet(wallet_name='hww_hot_key', external_signer=True, disable_private_keys=False)
        hww_hot_key = self.nodes[1].get_wallet_rpc('hww_hot_key')
        hot_desc = descsum_create(f"wpkh({ExtendedPrivateKey.generate().to_string()}/<0;1>/*)")
        result = hww_hot_key.importdescriptors([{
            "desc": hot_desc,
            "active": True,
            "timestamp": "now",
        }])
        assert_equal(result[0]["success"], True)

        hot_address = hww_hot_key.getnewaddress(address_type="bech32")
        self.nodes[0].sendtoaddress(hot_address, 1)
        self.generate(self.nodes[0], 1, sync_fun=self.sync_except_mock)
        hot_utxo = hww_hot_key.listunspent(addresses=[hot_address])[0]

        dest = self.nodes[0].getnewaddress()
        res = hww_hot_key.send(outputs={dest: 0.5}, inputs=[hot_utxo], add_inputs=False, add_to_wallet=False)
        assert res["complete"]
        assert self.nodes[1].testmempoolaccept([res["hex"]])[0]["allowed"]

    def test_unusual_signer(self):
        self.log.info('Test unusual but acceptable external signer behavior')
        hww = self.nodes[1].get_wallet_rpc('hww')

        # Spend a segwit and a taproot UTXO, to cover both ECDSA and schnorr
        # signatures
        addresses = [hww.getnewaddress(address_type="bech32"), hww.getnewaddress(address_type="bech32m")]
        for address in addresses:
            self.nodes[0].sendtoaddress(address, 1)
        self.generate(self.nodes[0], 1, sync_fun=self.sync_except_mock)
        inputs = [{"txid": utxo["txid"], "vout": utxo["vout"]} for utxo in hww.listunspent(addresses=addresses)]
        assert_equal(len(inputs), 2)
        dest = self.nodes[0].getnewaddress()

        self.log.info('The signer may strip fields it does not need')
        self.set_mock_sign_mode(self.nodes[1], "strip")
        res = hww.send(outputs={dest: 1.5}, inputs=inputs, add_inputs=False, add_to_wallet=False)
        assert res["complete"]
        assert hww.testmempoolaccept([res["hex"]])[0]["allowed"]

        self.log.info('The signer may use SIGHASH_ANYONECANPAY, which still commits to all outputs')
        self.set_mock_sign_mode(self.nodes[1], "sighash_all_anyonecanpay")
        res = hww.send(outputs={dest: 1.5}, inputs=inputs, add_inputs=False, add_to_wallet=False)
        assert res["complete"]
        assert hww.testmempoolaccept([res["hex"]])[0]["allowed"]

        self.clear_mock_sign_mode(self.nodes[1])

    def test_misbehaving_signer(self):
        self.log.info('Test misbehaving external signer')
        hww = self.nodes[1].get_wallet_rpc('hww')

        # Spend a segwit and a taproot UTXO, to cover both ECDSA and schnorr
        # signatures
        addresses = [hww.getnewaddress(address_type="bech32"), hww.getnewaddress(address_type="bech32m")]
        for address in addresses:
            self.nodes[0].sendtoaddress(address, 1)
        self.generate(self.nodes[0], 1, sync_fun=self.sync_except_mock)
        inputs = [{"txid": utxo["txid"], "vout": utxo["vout"]} for utxo in hww.listunspent(addresses=addresses)]
        assert_equal(len(inputs), 2)
        dest = self.nodes[0].getnewaddress()

        self.log.info('The signer must not tamper with the transaction')
        for mode in ["change_amount", "change_script", "remove_output"]:
            self.set_mock_sign_mode(self.nodes[1], mode)
            with self.nodes[1].assert_debug_log(["Signer returned a PSBT for a different transaction"]):
                assert_raises_rpc_error(-25, "External signer failed to sign", hww.send, outputs={dest: 1.5}, inputs=inputs, add_inputs=False)

        self.log.info('The signer must not use unsafe sighash types')
        # The first mode declares the sighash type in the PSBT, the second
        # leaves it out, so only the signatures themselves reveal it
        for mode in ["sighash_none", "sighash_none_hidden"]:
            self.set_mock_sign_mode(self.nodes[1], mode)
            with self.nodes[1].assert_debug_log(["Signer used an unsafe sighash type: NONE"]):
                assert_raises_rpc_error(-25, "External signer failed to sign", hww.send, outputs={dest: 1.5}, inputs=inputs, add_inputs=False)

        self.clear_mock_sign_mode(self.nodes[1])

        # The same transaction is accepted from a well-behaved signer
        res = hww.send(outputs={dest: 1.5}, inputs=inputs, add_inputs=False, add_to_wallet=False)
        assert res["complete"]

    def test_disconnected_signer(self):
        self.log.info('Test disconnected external signer')

        # First create a wallet with the signer connected
        self.nodes[1].createwallet(wallet_name='hww_disconnect', external_signer=True)
        hww = self.nodes[1].get_wallet_rpc('hww_disconnect')
        assert_equal(hww.getwalletinfo()["external_signer"], True)

        # Fund wallet
        self.nodes[0].sendtoaddress(hww.getnewaddress(address_type="bech32m"), 1)
        self.generate(self.nodes[0], 1, sync_fun=self.sync_except_mock)

        # Restart node with no signer connected
        self.log.debug(f"-signer={self.mock_signer_path('no_signer.py')}")
        self.restart_node(1, [f"-signer={self.mock_signer_path('no_signer.py')}", "-keypool=10"])
        self.nodes[1].loadwallet('hww_disconnect')
        hww = self.nodes[1].get_wallet_rpc('hww_disconnect')

        # Try to spend
        dest = hww.getrawchangeaddress()
        assert_raises_rpc_error(-25, "External signer not found", hww.send, outputs=[{dest:0.5}])

    def test_invalid_signer(self):
        self.log.debug(f"-signer={self.mock_signer_path('invalid_signer.py')}")
        self.log.info('Test invalid external signer')
        assert_raises_rpc_error(-1, "Invalid descriptor", self.nodes[1].createwallet, wallet_name='hww_invalid', external_signer=True)

    def test_multiple_signers(self):
        self.log.debug(f"-signer={self.mock_signer_path('multi_signers.py')}")
        self.log.info('Test multiple external signers')

        assert_raises_rpc_error(-1, "More than one external signer found", self.nodes[1].createwallet, wallet_name='multi_hww', external_signer=True)

    def test_descriptor_registration(self):
        self.log.debug(f"-signer={self.mock_signer_path()}")
        self.log.info('Register a descriptor with an external signer')

        self.nodes[1].createwallet(wallet_name='hww_registered', disable_private_keys=True, external_signer=True, blank=True)
        wallet = self.nodes[1].get_wallet_rpc('hww_registered')
        self.log.debug(wallet.getwalletinfo())
        # With blank=True the wallet starts empty: no device single-sig
        # descriptors are auto-imported, so the only descriptor present
        # after importdescriptors is the multisig descriptor under test.
        assert_equal(wallet.listdescriptors()["descriptors"], [])

        # e.g. obtained via hwi getxpub
        device_key = "[00000001/47h/1h/0h]tpubD6NzVbkrYhZ4YNXVQbNhMK1WqguFsUXceaVJKbmno2aZ3B6QfbMeraaYvnBSGpV3vxLyTTK9DYT1yoEck4XUScMzXoQ2U2oSmE2JyMedq3H"
        # for this test it doesn't matter that we can't actually sign with it
        our_key = "[00000001/47h/1h/0h]tpubDAXcJ7s7ZwicqjprRaEWdPoHKrCS215qxGYxpusRLLmJuT69ZSicuGdSfyvyKpvUNYBW1s2U3NSrT6vrCYB9e6nZUEvrqnwXPF8ArTCRXMY"

        res = wallet.importdescriptors([{
            "desc": descsum_create(f"wsh(multi(2,{device_key}/<0;1>/*,{our_key}/<0;1>/*))"),
            "active": True,
            "timestamp": "now"
        }])
        assert_equal(res[0]["success"], True)

        self.log.debug(wallet.listdescriptors())

        res = wallet.registerdescriptor()
        registration = res["registrations"][0]["registration"]
        assert_equal(registration, "cmRlc2MBBHRlc3Q=")

        info = wallet.getwalletinfo()
        assert_equal(info["external_signer_registrations"][0]["registration"], registration)

        # Make sure it's persisted
        self.nodes[1].unloadwallet("hww_registered")
        self.nodes[1].loadwallet("hww_registered")
        wallet = self.nodes[1].get_wallet_rpc('hww_registered')

        info = wallet.getwalletinfo()
        assert_equal(info["external_signer_registrations"][0]["registration"], registration)


if __name__ == '__main__':
    WalletSignerTest(__file__).main()

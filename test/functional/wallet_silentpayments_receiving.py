#!/usr/bin/env python3

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_approx,
    assert_equal,
    assert_raises_rpc_error,
)


class SilentPaymentsReceivingTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def test_encrypt_and_decrypt(self):
        self.log.info("Check that a silent payments wallet can be encrypted and decrypted")
        self.log.info("Create encrypted wallet")
        self.nodes[0].createwallet(wallet_name="sp_encrypted", passphrase="unsigned integer", silent_payment=True)
        wallet = self.nodes[0].get_wallet_rpc("sp_encrypted")
        addr = wallet.getnewaddress(address_type="silent-payment")
        self.def_wallet.sendtoaddress(addr, 10)
        self.generate(self.nodes[0], 1)
        self.log.info("Check that we can scan without the wallet being unlocked")
        assert_equal(wallet.getbalance(), 10)
        self.log.info("Check that we get an error if trying to send with the wallet locked")
        assert_raises_rpc_error(-13, "Error: Please enter the wallet passphrase with walletpassphrase first.", wallet.sendtoaddress, addr, 9)
        wallet.walletpassphrase(passphrase="unsigned integer", timeout=3)
        self.log.info("Unlock wallet and send")
        wallet.sendtoaddress(addr, 9)
        self.generate(self.nodes[0], 1)
        assert_approx(wallet.getbalance(), 10, 0.0001)

    def test_encrypting_unencrypted(self):
        self.log.info("Check that a silent payments wallet can be encrypted after creation")
        self.log.info("Create un-encrypted wallet")
        self.nodes[0].createwallet(wallet_name="sp_unencrypted", silent_payment=True)
        wallet = self.nodes[0].get_wallet_rpc("sp_unencrypted")
        addr = wallet.getnewaddress(address_type="silent-payment")
        self.def_wallet.sendtoaddress(addr, 10)
        self.generate(self.nodes[0], 1)
        assert_equal(wallet.getbalance(), 10)
        self.log.info("Add a passphrase to the wallet")
        wallet.encryptwallet(passphrase="unsigned integer")
        self.log.info("Check that we get an error if trying to send with the wallet locked")
        assert_raises_rpc_error(-13, "Error: Please enter the wallet passphrase with walletpassphrase first.", wallet.sendtoaddress, addr, 9)
        wallet.walletpassphrase(passphrase="unsigned integer", timeout=3)
        self.log.info("Unlock wallet and send")
        wallet.sendtoaddress(addr, 9)
        self.generate(self.nodes[0], 1)
        assert_approx(wallet.getbalance(), 10, 0.0001)

    def test_createwallet(self):
        self.log.info("Check createwallet silent payments option")

        self.nodes[0].createwallet(wallet_name="sp", silent_payment=True)
        wallet = self.nodes[0].get_wallet_rpc("sp")
        addr = wallet.getnewaddress(address_type="silent-payment")
        assert addr.startswith("sp")

        self.nodes[0].createwallet(wallet_name="non_sp", silent_payment=False)
        wallet = self.nodes[0].get_wallet_rpc("non_sp")
        assert_raises_rpc_error(-12, "Error: No silent-payment addresses available", wallet.getnewaddress, address_type="silent-payment")

        if self.is_bdb_compiled():
            assert_raises_rpc_error(-4, "Wallet with silent payments must also be a descriptor wallet", self.nodes[0].createwallet, wallet_name="legacy_sp", descriptors=False, silent_payment=True)

            self.nodes[0].createwallet(wallet_name="legacy_sp", descriptors=False)
            wallet = self.nodes[0].get_wallet_rpc("legacy_sp")
            assert_raises_rpc_error(-12, "Error: No silent-payment addresses available", wallet.getnewaddress, address_type="silent-payment")

    def test_basic(self):
        self.log.info("Basic receive and send")

        self.nodes[0].createwallet(wallet_name="basic", silent_payment=True)
        wallet = self.nodes[0].get_wallet_rpc("basic")

        addr = wallet.getnewaddress(address_type="silent-payment")
        txid = self.def_wallet.sendtoaddress(addr, 10)
        self.generate(self.nodes[0], 1)

        assert_equal(wallet.getbalance(), 10)
        wallet.gettransaction(txid)

        self.log.info("Test getnewaddress returns new labelled address")
        new_addr = wallet.getnewaddress(address_type="silent-payment")
        assert new_addr != addr
        txid = self.def_wallet.sendtoaddress(new_addr, 10)
        self.generate(self.nodes[0], 1)

        assert_equal(wallet.getbalance(), 20)
        wallet.gettransaction(txid)

        self.log.info("Test self-transfer")
        txid = wallet.send({addr: 5})
        self.generate(self.nodes[0], 1)
        assert_approx(wallet.getbalance(), 20, 0.0001)

        wallet.sendall([self.def_wallet.getnewaddress()])
        self.generate(self.nodes[0], 1)

        assert_equal(wallet.getbalance(), 0)

    def run_test(self):
        self.def_wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        self.generate(self.nodes[0], 101)

        self.test_createwallet()
        self.test_encrypt_and_decrypt()
        self.test_encrypting_unencrypted()
        self.test_basic()


if __name__ == '__main__':
    SilentPaymentsReceivingTest().main()

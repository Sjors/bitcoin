#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test external signer registered over the IPC (multiprocess) interface.

Instead of spawning a -signer command per operation, the signer connects to
the node's -ipcbind socket and registers itself via Init.registerExternalSigner.
This test wraps the mocks/signer.py command mock in a Cap'n Proto service, so
the signing behavior (including the misbehaving modes) matches wallet_signer.py
and only the transport differs.

See also wallet_signer.py for the -signer command transport.
"""
import asyncio
import base64
import json
import os
import subprocess
import sys

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)
from test_framework.ipc_util import load_capnp_modules

# Test may be skipped and not have capnp installed
try:
    import capnp  # type: ignore[import] # noqa: F401
except ModuleNotFoundError:
    pass


class WalletSignerIPCTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.extra_args = [
            [],
            # Note: no -signer. The signer service registers over IPC.
            ["-keypool=10"],
            # Node for the signer mock's wallet, kept offline so the mock
            # can't cheat by e.g. inspecting the UTXO set
            ["-maxconnections=0"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_ipc()
        self.skip_if_no_py_capnp()
        self.skip_if_no_external_signer()
        self.skip_if_no_wallet()

    def setup_nodes(self):
        self.extra_init = [{}, {"ipcbind": True}, {}]
        super().setup_nodes()
        self.capnp_modules = load_capnp_modules(self.config)

    def setup_network(self):
        self.setup_nodes()
        # Leave the signer mock's node disconnected
        self.connect_nodes(0, 1)

    def sync_except_mock(self):
        """Sync all nodes except the signer mock's, which never receives blocks."""
        self.sync_all(self.nodes[0:2])

    def mock_signer_path(self):
        return os.path.join(os.path.dirname(os.path.realpath(__file__)), 'mocks', 'signer.py')

    def set_mock_result(self, res):
        with open(os.path.join(self.nodes[1].cwd, "mock_result"), "w") as f:
            f.write(res)

    def clear_mock_result(self):
        os.remove(os.path.join(self.nodes[1].cwd, "mock_result"))

    def init_mock_node(self):
        """Hand the signer mock its dedicated offline node, on which it
        creates the wallet it signs with."""
        signer_node = self.nodes[2]
        assert_equal(signer_node.getconnectioncount(), 0)
        with open(os.path.join(self.nodes[1].cwd, "mock_rpc_url"), "w") as f:
            f.write(signer_node.url)

    def make_mock_signer(self):
        """Create a Cap'n Proto ExternalSignerService server which delegates
        every call to the mocks/signer.py command mock."""
        mock_path = self.mock_signer_path()
        cwd = self.nodes[1].cwd
        log = self.log

        class MockSigner(self.capnp_modules["signer"].ExternalSignerService.Server):
            def _run(self, args):
                res = subprocess.run([sys.executable, mock_path, *args], cwd=cwd,
                                     stdin=subprocess.DEVNULL, capture_output=True, text=True)
                log.debug(f"mock signer {args[-1] if args else ''}: exit {res.returncode}")
                if res.returncode != 0:
                    raise RuntimeError(f"mock signer exited with {res.returncode}: {res.stderr.strip()}")
                return json.loads(res.stdout)

            async def enumerate(self, chain, _context, **kwargs):
                signers = self._run(["--chain", chain, "enumerate"])
                _context.results.result = [
                    {"fingerprint": s["fingerprint"], "name": s.get("model", "")}
                    for s in signers if "fingerprint" in s
                ]

            async def getDescriptors(self, fingerprint, chain, account, _context, **kwargs):
                res = self._run(["--fingerprint", fingerprint, "--chain", chain,
                                 "getdescriptors", "--account", str(account)])
                r = _context.results
                if "error" in res:
                    r.error = res["error"]
                    r.result = False
                else:
                    r.receive = res["receive"]
                    r.internal = res["internal"]
                    r.result = True

            async def displayAddress(self, fingerprint, chain, descriptor, _context, **kwargs):
                res = self._run(["--fingerprint", fingerprint, "--chain", chain,
                                 "displayaddress", "--desc", descriptor])
                r = _context.results
                if "error" in res:
                    r.error = res["error"]
                    r.result = False
                else:
                    r.address = res["address"]
                    r.result = True

            async def signTransaction(self, fingerprint, chain, psbt, _context, **kwargs):
                psbt_b64 = base64.b64encode(bytes(psbt)).decode("ascii")
                res = self._run(["--fingerprint", fingerprint, "--chain", chain,
                                 "signtx", psbt_b64])
                r = _context.results
                if "error" in res:
                    r.error = res["error"]
                    r.result = False
                else:
                    r.signedPsbt = base64.b64decode(res["psbt"])
                    r.result = True

        return MockSigner()

    async def register_signer(self):
        """Open a new IPC connection and register a mock signer on it.
        Returns the connection and its client object, which must be kept
        alive; closing the connection unregisters the signer (lazily)."""
        connection = await capnp.AsyncIoStream.create_unix_connection(self.nodes[1].ipc_socket_path)
        client = capnp.TwoPartyClient(connection)
        init = client.bootstrap().cast_as(self.capnp_modules["init"].Init)
        # Note: no Init.construct() call. The signer methods carry no
        # Proxy.Context, so no thread map is needed in either direction.
        await init.registerExternalSigner(self.make_mock_signer())
        return connection, client

    def run_test(self):
        self.init_mock_node()

        async def async_routine():
            self.log.info("Register mock signer over IPC")
            connection, client = await self.register_signer()

            # Run the synchronous RPC assertions in a worker thread so the
            # event loop stays free to serve incoming signer calls.
            await asyncio.to_thread(self.test_valid_signer)

            self.log.info("Disconnect the signer service")
            connection.close()
            await asyncio.to_thread(self.test_disconnected_signer)

            self.log.info("Re-register the signer service")
            connection, client = await self.register_signer()
            await asyncio.to_thread(self.test_reconnected_signer)

            self.log.info("Test a signer service which throws")
            await asyncio.to_thread(self.test_throwing_signer)

            # The throwing call cleared the registration; register once more
            # to check the node did not end up in a broken state.
            connection, client = await self.register_signer()
            await asyncio.to_thread(self.test_reregistered_after_throw)

        asyncio.run(capnp.run(async_routine()))

    def test_valid_signer(self):
        # Create new wallets for an external signer.
        # disable_private_keys and descriptors must be true:
        assert_raises_rpc_error(-4, "Private keys must be disabled when using an external signer", self.nodes[1].createwallet, wallet_name='not_hww', disable_private_keys=False, external_signer=True)
        self.nodes[1].createwallet(wallet_name='hww', disable_private_keys=True, external_signer=True)
        hww = self.nodes[1].get_wallet_rpc('hww')
        assert_equal(hww.getwalletinfo()["external_signer"], True)

        self.log.info('Test enumeratesigners')
        signers = self.nodes[1].enumeratesigners()['signers']
        assert_equal(len(signers), 1)
        assert_equal(signers[0]['fingerprint'], '00000001')
        assert_equal(signers[0]['name'], 'trezor_t')

        assert_equal(hww.getwalletinfo()["keypoolsize"], 40)

        address1 = hww.getnewaddress(address_type="bech32")
        assert_equal(address1, "bcrt1qm90ugl4d48jv8n6e5t9ln6t9zlpm5th68x4f8g")
        address_info = hww.getaddressinfo(address1)
        assert_equal(address_info['solvable'], True)
        assert_equal(address_info['ismine'], True)
        assert_equal(address_info['hdkeypath'], "m/84h/1h/0h/0/0")

        address2 = hww.getnewaddress(address_type="p2sh-segwit")
        assert_equal(address2, "2N2gQKzjUe47gM8p1JZxaAkTcoHPXV6YyVp")
        address3 = hww.getnewaddress(address_type="legacy")
        assert_equal(address3, "n1LKejAadN6hg2FrBXoU1KrwX4uK16mco9")
        address4 = hww.getnewaddress(address_type="bech32m")
        assert_equal(address4, "bcrt1phw4cgpt6cd30kz9k4wkpwm872cdvhss29jga2xpmftelhqll62ms4e9sqj")

        self.log.info('Test walletdisplayaddress')
        for address in [address1, address2, address3]:
            result = hww.walletdisplayaddress(address)
            assert_equal(result, {"address": address})

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

        self.log.info('Test send using hww')
        # Spend all four address types at once. Don't broadcast the transaction
        # yet so the RPC returns the raw hex.
        res = hww.send(outputs={dest: 3.5}, add_to_wallet=False)
        assert res["complete"]
        assert_equal(len(hww.decoderawtransaction(res["hex"])["vin"]), 4)
        assert hww.testmempoolaccept([res["hex"]])[0]["allowed"]

        self.log.info('Test sendall using hww')
        res = hww.sendall(recipients=[{dest: 3.5}, hww.getrawchangeaddress()], add_to_wallet=False)
        assert res["complete"]
        assert hww.testmempoolaccept([res["hex"]])[0]["allowed"]
        # Broadcast transaction so we can bump the fee
        hww.sendrawtransaction(res["hex"])

        self.log.info('Test bumpfee using hww')
        orig_tx_id = res["txid"]
        res = hww.bumpfee(orig_tx_id)
        assert_greater_than(res["fee"], res["origfee"])
        assert_equal(res["errors"], [])

    def test_disconnected_signer(self):
        self.log.info('Test disconnected signer service')
        hww = self.nodes[1].get_wallet_rpc('hww')

        # Fund the wallet, which needs no signer: addresses come from the
        # keypool filled when the wallet was created.
        self.nodes[0].sendtoaddress(hww.getnewaddress(address_type="bech32"), 1)
        self.generate(self.nodes[0], 1, sync_fun=self.sync_except_mock)

        # The registration is cleaned up lazily: the first operation fails on
        # the stale capability and clears it, reporting no signers.
        assert_raises_rpc_error(-25, "External signer not found", hww.send, outputs=[{hww.getrawchangeaddress(): 0.5}])

        # With the registration cleared and no -signer command configured,
        # further operations report that no signer is configured at all.
        assert_raises_rpc_error(-1, "Error: restart bitcoind with -signer=<cmd>", self.nodes[1].enumeratesigners)

    def test_reconnected_signer(self):
        self.log.info('Test signer service after re-registration')
        signers = self.nodes[1].enumeratesigners()['signers']
        assert_equal(len(signers), 1)
        assert_equal(signers[0]['fingerprint'], '00000001')

        hww = self.nodes[1].get_wallet_rpc('hww')
        dest = self.nodes[0].getnewaddress()
        res = hww.send(outputs={dest: 0.1}, add_to_wallet=False)
        assert res["complete"]

    def test_throwing_signer(self):
        self.log.info('Test signer service raising a remote exception')
        # Making the mock exit non-zero makes the service wrapper raise,
        # which reaches the node as a transport-level (ipc::Exception)
        # failure and clears the registration.
        self.set_mock_result("2")
        assert_raises_rpc_error(-1, "No external signers found",
            self.nodes[1].createwallet, wallet_name='hww2', disable_private_keys=True, external_signer=True
        )
        self.clear_mock_result()

        # The registration was cleared by the failed call
        assert_raises_rpc_error(-1, "Error: restart bitcoind with -signer=<cmd>", self.nodes[1].enumeratesigners)

    def test_reregistered_after_throw(self):
        self.log.info('Test recovery after a remote exception')
        # Note: the failed createwallet above left a partial hww2 database
        # behind, so use a fresh name.
        self.nodes[1].createwallet(wallet_name='hww3', disable_private_keys=True, external_signer=True)
        hww3 = self.nodes[1].get_wallet_rpc('hww3')
        assert_equal(hww3.getwalletinfo()["external_signer"], True)


if __name__ == '__main__':
    WalletSignerIPCTest(__file__).main()

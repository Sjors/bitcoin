#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test MuSig2 descriptors in an external-signer wallet."""
import json
import os

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


# The single mocked external signer device used by the hot+device
# subtests below is backed by a real cosigner wallet on the offline mock node; the
# device's xprv, xpub, fingerprint and BIP32 origin are all derived
# from that wallet at runtime in `_setup_device_wallet`.
DEVICE_ACCOUNT_PATH = "m/87h/1h/0h"


class WalletSignerMuSig2Test(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.extra_args = [
            [],
            [f"-signer={self.mock_signer_path()}", '-keypool=10'],
            ["-maxconnections=0"],
        ]

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)

    def sync_except_mock(self):
        self.sync_all(self.nodes[0:2])

    def skip_test_if_missing_module(self):
        self.skip_if_no_external_signer()
        self.skip_if_no_wallet()

    def run_test(self):
        self.def_wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        self._init_mock_node()
        self._setup_device_wallet()
        self.test_create_wallet()
        self.test_register()
        self.test_display_address()
        self.test_registered_musig2()
        self.test_registered_musig2_two_signers()

    def _setup_device_wallet(self):
        """Create the cosigner wallet on the offline mock node that backs the
        external signer device. The mock binary delegates `signtx` to
        this wallet via RPC, so the device contributes a real
        MuSig2 pubnonce and partial signature on each round instead of
        replaying a pre-staged PSBT."""
        device = self._make_device_cosigner('hww_musig_device')
        self.device_wallet = device['wallet']
        self.device_origin = device['origin']
        self.device_xpub = device['xpub']
        self.device_xprv = device['xprv']
        self.device_fingerprint = device['fingerprint']
        self._set_mock_signers([device])

    def _init_mock_node(self):
        assert_equal(self.nodes[2].getconnectioncount(), 0)
        with open(os.path.join(self.nodes[1].cwd, "mock_rpc_url"), "w") as f:
            f.write(self.nodes[2].url)

    def _set_mock_signers(self, devices):
        """Expose device wallets on the offline mock node as signers."""
        with open(os.path.join(self.nodes[1].cwd, "mock_signers"), "w") as f:
            json.dump({device['fingerprint']: device['name'] for device in devices}, f)

    def test_create_wallet(self):
        self.log.info('Create an external-signer wallet with a MuSig2 descriptor')

        # Blank wallet so signer setup doesn't auto-import the device's
        # placeholder single-sig descriptors. Add a hot HD seed locally and
        # import an xpub-only descriptor; Sjors/bitcoin#127 fills in the
        # matching private key while parsing it.
        self.nodes[1].createwallet(
            wallet_name='hww_musig',
            external_signer=True,
            disable_private_keys=False,
            blank=True,
        )
        hww_musig = self.nodes[1].get_wallet_rpc('hww_musig')
        hww_musig.addhdkey()
        local_info = hww_musig.derivehdkey(DEVICE_ACCOUNT_PATH, {"private": True})

        musig_descriptor = (
            f"tr(musig({local_info['origin']}{local_info['xpub']},"
            f"{self.device_origin}{self.device_xpub})/<0;1>/*)"
        )
        result = hww_musig.importdescriptors([{
            "desc": descsum_create(musig_descriptor),
            "active": True,
            "timestamp": "now",
        }])
        assert_equal(result[0]["success"], True)

        # Mirror the descriptor on the device cosigner wallet (with the
        # device xprv and the local xpub) so the mock signer can
        # contribute its real MuSig2 nonce and partial signature when
        # the wallet calls signtx.
        device_descriptor = (
            f"tr(musig({self.device_origin}{self.device_xprv},"
            f"{local_info['origin']}{local_info['xpub']})/<0;1>/*)"
        )
        result = self.device_wallet.importdescriptors([{
            "desc": descsum_create(device_descriptor),
            "active": True,
            "timestamp": "now",
        }])
        assert_equal(result[0]["success"], True)
        descs = hww_musig.listdescriptors()["descriptors"]
        active_musig = [d for d in descs if d["active"] and d["desc"].startswith("tr(musig(")]
        # One active descriptor each for receive and change.
        assert_equal(len(active_musig), 2)

    def test_register(self):
        self.log.info('Register the MuSig2 descriptor')
        hww_musig = self.nodes[1].get_wallet_rpc('hww_musig')
        res = hww_musig.registerdescriptor()
        assert_equal(len(res["registrations"]), 1)
        assert_equal(res["registrations"][0]["fingerprint"], self.device_fingerprint)
        info = hww_musig.getwalletinfo()
        assert_equal(len(info["external_signer_registrations"]), 1)
        assert_equal(info["external_signer_registrations"][0]["fingerprint"], self.device_fingerprint)

    def test_display_address(self):
        self.log.info('Display an address from the MuSig2 descriptor')
        hww_musig = self.nodes[1].get_wallet_rpc('hww_musig')

        addr = hww_musig.getnewaddress(address_type="bech32m")
        addr_info = hww_musig.getaddressinfo(addr)
        assert_equal(addr_info["ismine"], True)
        assert_equal(addr_info["solvable"], True)
        # The wallet has a registered descriptor whose fingerprint
        # matches the connected mock device, so walletdisplayaddress
        # dispatches through DisplayAddressRegistered. Stage the address
        # for the device to echo back.
        mock_display_path = os.path.join(self.nodes[1].cwd, "mock_displayaddress")
        with open(mock_display_path, "w") as f:
            f.write(addr)
        assert_equal(hww_musig.walletdisplayaddress(addr), {"address": addr})
        os.remove(mock_display_path)

    def _set_musig_mock_state(self, *, error=None, crash=None, reset_counter=True):
        """Drop mock state files in node 1's cwd. None means leave existing
        file in place; '' means remove the file."""
        cwd = self.nodes[1].cwd
        for name, value in (
            ('mock_signtx_error', error),
            ('mock_signtx_crash', crash),
        ):
            path = os.path.join(cwd, name)
            if value is None:
                continue
            if value == '':
                if os.path.isfile(path):
                    os.remove(path)
                continue
            with open(path, 'w') as f:
                f.write(value)
        if reset_counter:
            for filename in os.listdir(cwd):
                if filename.startswith('mock_signtx_') and filename.endswith('_counter'):
                    os.remove(os.path.join(cwd, filename))

    def test_registered_musig2(self):
        self.log.info("Test MuSig2 registered-descriptor signing dance via mock signer")
        hww = self.nodes[1].get_wallet_rpc('hww_musig')

        # Fund the wallet at the first MuSig2 receive address.
        addr = hww.getnewaddress(address_type="bech32m")
        self.def_wallet.sendtoaddress(addr, 1)
        self.generate(self.nodes[0], 1, sync_fun=self.sync_except_mock)

        # Send via the external-signer wallet. `send` funds, signs and
        # broadcasts in one RPC: CWallet::FillPSBT dispatches through
        # FillPSBTRegistered, the round-1 fan-out collects the device
        # pubnonce and the local SPKM contributes the matching nonce,
        # the round-2 retry inside FillPSBT collects the device's
        # partial sig and the local SPKM produces its own, and
        # FinalizePSBT aggregates the two psigs into a Schnorr
        # key-path signature. Both contributions come from real
        # MuSig2 signers (the local descriptor + the cosigner wallet
        # on node 0 driven by the mock subprocess). Nothing is
        # replayed.
        dest = self.def_wallet.getnewaddress(address_type="bech32m")
        result = hww.send(outputs=[{dest: 0.5}])
        assert_equal(result["complete"], True)
        # The mock saw two signtx calls (round 1 + round 2).
        with open(os.path.join(self.nodes[1].cwd,
                               f'mock_signtx_{self.device_fingerprint}_counter')) as f:
            assert_equal(f.read().strip(), "2")
        # `send` already broadcast the tx; mempool acceptance verifies
        # the aggregated MuSig2 signature is valid.
        assert result["txid"] in self.nodes[1].getrawmempool()

        # Build a stand-alone PSBT for the soft- and hard-fail subtests
        # below; using the same PSBT through both subtests lets us
        # assert the local nonce is preserved across calls without
        # racing the broadcast of the optimistic path. Fund a second
        # UTXO since `send` consumed the first.
        addr = hww.getnewaddress(address_type="bech32m")
        self.def_wallet.sendtoaddress(addr, 1)
        self.generate(self.nodes[0], 1, sync_fun=self.sync_except_mock)
        psbt = hww.walletcreatefundedpsbt(inputs=[], outputs=[{dest: 0.5}])["psbt"]

        # --- Soft-fail path ---
        # Configure the mock to return a structured signer error from
        # signtx. Because the local SPKM has an xprv and contributed
        # its MuSig2 pubnonce in the round-1 fan-out, FillPSBTRegistered
        # soft-fails the device's signtx so that fresh local
        # contribution isn't discarded: the caller can re-issue
        # walletprocesspsbt once the device is back to drive round 2.
        self._set_musig_mock_state(error="device disconnected")
        result = hww.walletprocesspsbt(psbt=psbt)
        assert_equal(result["complete"], False)
        # The local nonce now lives in the returned PSBT. Re-issuing
        # walletprocesspsbt on that PSBT exercises the hard-fail branch:
        # the local pass is a no-op (its pubnonce is already there), so
        # FillPSBTRegistered can't justify hiding the device error and
        # surfaces it as EXTERNAL_SIGNER_FAILED.
        psbt_with_nonce = result["psbt"]
        assert_raises_rpc_error(
            -25, "External signer failed to sign",
            hww.walletprocesspsbt, psbt=psbt_with_nonce,
        )

        # --- Subprocess-crash path ---
        # `signer.py` exiting non-zero used to escape FillPSBTRegistered as
        # an uncaught std::runtime_error and bubble up as an opaque
        # internal JSON-RPC error. Commit "external signer: surface
        # SignTransactionRegistered crash as signer error" routes that
        # through the same uniform soft/hard-fail logic as a structured
        # signer error.
        self._set_musig_mock_state(error='', crash='1')
        assert_raises_rpc_error(
            -25, "External signer failed to sign",
            hww.walletprocesspsbt, psbt=psbt_with_nonce,
        )
        # Reset state so subsequent tests aren't affected.
        self._set_musig_mock_state(crash='')

    def test_registered_musig2_two_signers(self):
        self.log.info("Test MuSig2 registered-descriptor signing with two external signers")
        # Two co-signing devices, both reachable through the same
        # `-signer` mock binary. After CWallet's registration dispatch was
        # taught to fan out to every connected signer (commit "wallet:
        # fan registerdescriptor/displayaddress/FillPSBT out to all
        # signers"), this scenario completes inside a single
        # walletprocesspsbt call: the round-1 fan-out collects every
        # cosigner's pubnonce, the round-2 retry inside FillPSBT
        # collects every partial sig, and FillPSBTRegistered's FinalizePSBT
        # aggregates them into a Schnorr key-path signature.

        # Clear failure/display state left by the single-device scenarios.
        cwd = self.nodes[1].cwd
        for stale in ('mock_signtx_error', 'mock_signtx_crash', 'mock_displayaddress'):
            stale_path = os.path.join(cwd, stale)
            if os.path.isfile(stale_path):
                os.remove(stale_path)

        # Two device-side cosigner wallets on the offline mock node, each with its own
        # xprv at the same BIP32 path. Together with the local mirror
        # held by the registered-descriptor wallet on node 1, this is a 2-of-2 MuSig2.
        device_a = self._make_device_cosigner('hww_musig_device_a')
        device_b = self._make_device_cosigner('hww_musig_device_b')

        # Wire the mock to enumerate both device wallets.
        self._set_mock_signers([device_a, device_b])

        # External signer wallet on node 1: no local privkeys (both cosigners are
        # devices), blank so signer setup doesn't auto-import single-sig
        # placeholder descriptors.
        self.nodes[1].createwallet(
            wallet_name='hww_registered_2of2',
            disable_private_keys=True,
            external_signer=True,
            blank=True,
        )
        hww = self.nodes[1].get_wallet_rpc('hww_registered_2of2')
        musig_descriptor = (
            f"tr(musig({device_a['origin']}{device_a['xpub']},"
            f"{device_b['origin']}{device_b['xpub']})/<0;1>/*)"
        )
        result = hww.importdescriptors([{
            "desc": descsum_create(musig_descriptor),
            "active": True,
            "timestamp": "now",
        }])
        assert_equal(result[0]["success"], True)

        # Mirror the same descriptor on each device wallet, with that
        # device's own xprv swapped in. The mock routes signtx to
        # these wallets so they produce real MuSig2 contributions.
        for device in (device_a, device_b):
            other = device_b if device is device_a else device_a
            mirror = (
                f"tr(musig({device['origin']}{device['xprv']},"
                f"{other['origin']}{other['xpub']})/<0;1>/*)"
            )
            res = device['wallet'].importdescriptors([{
                "desc": descsum_create(mirror),
                "active": True,
                "timestamp": "now",
            }])
            assert_equal(res[0]["success"], True)

        # registerdescriptor fans out: one registration per device.
        hww.registerdescriptor()
        info = hww.getwalletinfo()
        assert_equal(len(info["external_signer_registrations"]), 2)
        assert_equal({entry["fingerprint"] for entry in info["external_signer_registrations"]},
                     {device_a['fingerprint'], device_b['fingerprint']})

        # Fund the aggregated address.
        addr = hww.getnewaddress(address_type="bech32m")
        self.def_wallet.sendtoaddress(addr, 1)
        self.generate(self.nodes[0], 1, sync_fun=self.sync_except_mock)

        # Single RPC: round 1 fan-out + round 2 retry fan-out + finalize
        # all happen inside walletprocesspsbt.
        dest = self.def_wallet.getnewaddress(address_type="bech32m")
        psbt = hww.walletcreatefundedpsbt(inputs=[], outputs=[{dest: 0.5}],
                                          options={"change_type": "bech32m"})["psbt"]
        proc = hww.walletprocesspsbt(psbt=psbt)
        assert_equal(proc["complete"], True)
        # Both devices were invoked. The fan-out iterates signers in
        # order: round 1 calls each (collecting nonces, with the second
        # also producing a partial sig once both nonces are present);
        # round 2 calls the first signer again to add its partial sig
        # and finalize, after which the PSBT is complete and
        # FillPSBTRegistered short-circuits the remaining signers. So one
        # device sees two signtx calls and the other sees one.
        counters = sorted(
            int(open(os.path.join(cwd, f"mock_signtx_{d['fingerprint']}_counter")).read())
            for d in (device_a, device_b)
        )
        assert_equal(counters, [1, 2])
        assert self.nodes[0].testmempoolaccept([proc["hex"]])[0]["allowed"]

    def _make_device_cosigner(self, name):
        """Stand up a cosigner wallet on the offline node to back one mock device.
        Returns a dict with the wallet handle and the BIP32 material the
        registered-descriptor wallet's MuSig2 descriptor needs."""
        self.nodes[2].createwallet(wallet_name=name)
        wallet = self.nodes[2].get_wallet_rpc(name)
        wallet.addhdkey()
        info = wallet.derivehdkey(DEVICE_ACCOUNT_PATH, {"private": True})
        return {
            'name': name,
            'wallet': wallet,
            'origin': info["origin"],
            'xpub': info["xpub"],
            'xprv': info["xprv"],
            'fingerprint': info["origin"][1:9],
        }


if __name__ == '__main__':
    WalletSignerMuSig2Test(__file__).main()

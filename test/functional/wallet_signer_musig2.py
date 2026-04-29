#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test MuSig2 descriptors in an external-signer wallet."""
import os
import urllib.parse

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


# The single mocked external signer device used by the hot+device
# subtests below is backed by a real cosigner wallet on node 0; the
# device's xprv, xpub, fingerprint and BIP32 origin are all derived
# from that wallet at runtime in `_setup_device_wallet`.
DEVICE_ACCOUNT_PATH = "m/87h/1h/0h"

# Hardcode the local MuSig participant's account keys until the later
# importdescriptors autobind commit teaches the wallet to bind an xpub
# descriptor back to an xprv it already knows.
LOCAL_ORIGIN = "[ec63add0/84h/1h/0h]"
LOCAL_XPRV = "tprv8gauGKtmnH4cxv22ZtmEKqDDAeqnm2b4srPWuFsugMuVc79KDEHRTWgKGdAhACqjZQytU1o9gcc91TSW8L1s18PgFUHAJ8p8iY1GwaUEn9u"
LOCAL_XPUB = "tpubDDGwQjw1vekHrP3pTYRpjEsKjgMivMmyT9zJBmvD6dhtSbQ5qd71e1JBSm8XsPHiibVPfvpSsK1gffjHc2NLr9p2BebB6XRpyLih9E1j5nF"


class WalletSignerMuSig2Test(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [
            [],
            [f"-signer={self.mock_signer_path('signer_musig.py')}", '-keypool=10'],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_external_signer()
        self.skip_if_no_wallet()

    def run_test(self):
        self.def_wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        self._setup_device_wallet()
        self.test_create_wallet()
        self.test_register()
        self.test_display_address()
        self.test_bip388_musig2_policy()

    def _setup_device_wallet(self):
        """Create the cosigner wallet on node 0 that backs the mock
        external signer device. The mock binary delegates `signtx` to
        this wallet via JSON-RPC, so the device contributes a real
        MuSig2 pubnonce and partial signature on each round instead of
        replaying a pre-staged PSBT."""
        self.nodes[0].createwallet(wallet_name='hww_musig_device')
        self.device_wallet = self.nodes[0].get_wallet_rpc('hww_musig_device')
        self.device_wallet.addhdkey()
        info = self.device_wallet.derivehdkey(DEVICE_ACCOUNT_PATH, {"private": True})
        self.device_origin = info["origin"]
        self.device_xpub = info["xpub"]
        self.device_xprv = info["xprv"]
        # The fingerprint is the first 8 hex chars of the origin string
        # ([fingerprint/...]).
        self.device_fingerprint = self.device_origin[1:9]
        # Wire the mock to advertise this fingerprint from `enumerate`
        # and to delegate every `signtx` call to the device wallet.
        self._set_musig_mock_state(fingerprint=self.device_fingerprint)
        self._set_musig_signtx_delegate('hww_musig_device')

    def test_create_wallet(self):
        self.log.info('Create an external-signer wallet with a MuSig2 descriptor')

        # Blank wallet so signer setup doesn't auto-import the device's
        # placeholder single-sig descriptors.
        self.nodes[1].createwallet(
            wallet_name='hww_musig',
            external_signer=True,
            disable_private_keys=False,
            blank=True,
        )
        hww_musig = self.nodes[1].get_wallet_rpc('hww_musig')

        musig_descriptor = (
            f"tr(musig({LOCAL_ORIGIN}{LOCAL_XPRV},"
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
            f"{LOCAL_ORIGIN}{LOCAL_XPUB})/<0;1>/*)"
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
        self.log.info('Register the MuSig2 descriptor as a BIP388 policy')
        hww_musig = self.nodes[1].get_wallet_rpc('hww_musig')
        self._set_musig_registerpolicy_nohmac(True)
        res = hww_musig.registerpolicy()
        assert "hmac" not in res
        info = hww_musig.getwalletinfo()
        assert_equal(len(info["bip388"]), 1)
        assert_equal(info["bip388"][0]["fingerprint"], self.device_fingerprint)

    def test_display_address(self):
        self.log.info('Display an address from the MuSig2 descriptor')
        hww_musig = self.nodes[1].get_wallet_rpc('hww_musig')

        addr = hww_musig.getnewaddress(address_type="bech32m")
        addr_info = hww_musig.getaddressinfo(addr)
        assert_equal(addr_info["ismine"], True)
        assert_equal(addr_info["solvable"], True)
        # The wallet has a registered BIP388 policy whose fingerprint
        # matches the connected mock device, so walletdisplayaddress
        # dispatches through DisplayAddressPolicy. Stage the address
        # for the device to echo back.
        mock_display_path = os.path.join(self.nodes[1].cwd, "mock_displayaddress")
        with open(mock_display_path, "w") as f:
            f.write(addr)
        assert_equal(hww_musig.walletdisplayaddress(addr), {"address": addr})
        os.remove(mock_display_path)

    def _set_musig_mock_state(self, *, fingerprint=None, error=None,
                              reset_counter=True):
        """Drop mock state files in node 1's cwd. None means leave existing
        file in place; '' means remove the file."""
        cwd = self.nodes[1].cwd
        for name, value in (
            ('mock_fingerprint', fingerprint),
            ('mock_signtx_error', error),
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
            counter_path = os.path.join(cwd, 'mock_signtx_counter')
            if os.path.isfile(counter_path):
                os.remove(counter_path)

    def _set_musig_registerpolicy_nohmac(self, enabled):
        path = os.path.join(self.nodes[1].cwd, 'mock_registerpolicy_nohmac')
        if enabled:
            with open(path, 'w') as f:
                f.write('1')
        elif os.path.isfile(path):
            os.remove(path)

    def _set_musig_signtx_delegate(self, wallet_name, *, fingerprint=None):
        """Wire the mock signer's `signtx` to forward the incoming PSBT
        to `walletprocesspsbt` on the named wallet on node 0. Without
        `fingerprint`, applies to every device; with it, applies only
        to the given fingerprint (multi-device tests)."""
        name = 'mock_signtx_delegate_url' if fingerprint is None \
            else f'mock_signtx_delegate_{fingerprint}_url'
        node = self.nodes[0]
        wallet_url = f"{node.url}/wallet/{urllib.parse.quote(wallet_name)}"
        with open(os.path.join(self.nodes[1].cwd, name), 'w') as f:
            f.write(wallet_url)

    def test_bip388_musig2_policy(self):
        self.log.info("Test BIP388 MuSig2 policy signing dance via mock signer")
        hww = self.nodes[1].get_wallet_rpc('hww_musig')

        # Fund the wallet at the first MuSig2 receive address.
        addr = hww.getnewaddress(address_type="bech32m")
        self.def_wallet.sendtoaddress(addr, 1)
        self.generate(self.nodes[0], 1)

        # Send via the external-signer wallet. `send` funds, signs and
        # broadcasts in one RPC: CWallet::FillPSBT dispatches through
        # FillPSBTPolicy, the round-1 fan-out collects the device
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
        with open(os.path.join(self.nodes[1].cwd, 'mock_signtx_counter')) as f:
            assert_equal(f.read().strip(), "2")
        # `send` already broadcast the tx; mempool acceptance verifies
        # the aggregated MuSig2 signature is valid.
        assert result["txid"] in self.nodes[1].getrawmempool()

        # Build a stand-alone PSBT for the hard-fail subtest below. Fund
        # a second UTXO since `send` consumed the first.
        addr = hww.getnewaddress(address_type="bech32m")
        self.def_wallet.sendtoaddress(addr, 1)
        self.generate(self.nodes[0], 1)
        psbt = hww.walletcreatefundedpsbt(inputs=[], outputs=[{dest: 0.5}])["psbt"]

        # --- Hard-fail path ---
        # Configure the mock to return a structured signer error from
        # signtx. The wallet must surface EXTERNAL_SIGNER_FAILED rather
        # than silently returning the unchanged PSBT.
        self._set_musig_mock_state(error="device disconnected")
        assert_raises_rpc_error(
            -25, "External signer failed to sign",
            hww.walletprocesspsbt, psbt=psbt,
        )

if __name__ == '__main__':
    WalletSignerMuSig2Test(__file__).main()

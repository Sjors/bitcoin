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
        self.test_bip388_musig2_two_signers()

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
        # placeholder single-sig descriptors. We then add a hot HD seed
        # locally and import an xpub-only MuSig2 descriptor: the
        # `importdescriptors xprv autobind` path recognises the local
        # cosigner xpub as one of the wallet's own and binds the matching
        # xprv automatically.
        self.nodes[1].createwallet(
            wallet_name='hww_musig',
            external_signer=True,
            disable_private_keys=False,
            blank=True,
        )
        hww_musig = self.nodes[1].get_wallet_rpc('hww_musig')
        hww_musig.addhdkey()
        local_info = hww_musig.derivehdkey(DEVICE_ACCOUNT_PATH, {"private": True})
        self.local_xpub = local_info["xpub"]

        musig_descriptor = (
            f"tr(musig({local_info['origin']}{self.local_xpub},"
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
            f"{local_info['origin']}{self.local_xpub})/<0;1>/*)"
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

    def _set_musig_mock_state(self, *, fingerprint=None, error=None, crash=None,
                              reset_counter=True):
        """Drop mock state files in node 1's cwd. None means leave existing
        file in place; '' means remove the file."""
        cwd = self.nodes[1].cwd
        for name, value in (
            ('mock_fingerprint', fingerprint),
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
        self.generate(self.nodes[0], 1)
        psbt = hww.walletcreatefundedpsbt(inputs=[], outputs=[{dest: 0.5}])["psbt"]

        # --- Soft-fail path ---
        # Configure the mock to return a structured signer error from
        # signtx. Because the local SPKM has an xprv and contributed
        # its MuSig2 pubnonce in the round-1 fan-out, FillPSBTPolicy
        # soft-fails the device's signtx so that fresh local
        # contribution isn't discarded: the caller can re-issue
        # walletprocesspsbt once the device is back to drive round 2.
        self._set_musig_mock_state(error="device disconnected")
        result = hww.walletprocesspsbt(psbt=psbt)
        assert_equal(result["complete"], False)
        # The local nonce now lives in the returned PSBT. Re-issuing
        # walletprocesspsbt on that PSBT exercises the hard-fail branch:
        # the local pass is a no-op (its pubnonce is already there), so
        # FillPSBTPolicy can't justify hiding the device error and
        # surfaces it as EXTERNAL_SIGNER_FAILED.
        psbt_with_nonce = result["psbt"]
        assert_raises_rpc_error(
            -25, "External signer failed to sign",
            hww.walletprocesspsbt, psbt=psbt_with_nonce,
        )

        # --- Subprocess-crash path ---
        # `signer.py` exiting non-zero used to escape FillPSBTPolicy as
        # an uncaught std::runtime_error and bubble up as an opaque
        # internal JSON-RPC error. Commit "external signer: surface
        # SignTransactionPolicy crash as signer error" routes that
        # through the same uniform soft/hard-fail logic as a structured
        # signer error.
        self._set_musig_mock_state(error='', crash='1')
        assert_raises_rpc_error(
            -25, "External signer failed to sign",
            hww.walletprocesspsbt, psbt=psbt_with_nonce,
        )
        # Reset state so subsequent tests aren't affected.
        self._set_musig_mock_state(crash='')

    def test_bip388_musig2_two_signers(self):
        self.log.info("Test BIP388 MuSig2 policy signing dance with two external signers")
        # Two co-signing devices, both reachable through the same
        # `-signer` mock binary. After CWallet's BIP388 dispatch was
        # taught to fan out to every connected signer (commit "wallet:
        # fan registerpolicy/displayaddress/FillPSBT out to all
        # signers"), this scenario completes inside a single
        # walletprocesspsbt call: the round-1 fan-out collects every
        # cosigner's pubnonce, the round-2 retry inside FillPSBT
        # collects every partial sig, and FillPSBTPolicy's FinalizePSBT
        # aggregates them into a Schnorr key-path signature.

        # The single-device hww_musig leaves a delegate URL set; clear
        # it (and the single-device fingerprint slot) so each device
        # gets routed only via its own per-fingerprint delegate URL.
        cwd = self.nodes[1].cwd
        for stale in ('mock_signtx_delegate_url', 'mock_fingerprint',
                      'mock_signtx_counter', 'mock_signtx_error',
                      'mock_signtx_crash', 'mock_displayaddress'):
            stale_path = os.path.join(cwd, stale)
            if os.path.isfile(stale_path):
                os.remove(stale_path)

        # Two device-side cosigner wallets on node 0, each with its own
        # xprv at the same BIP32 path. Together with the local mirror
        # held by the BIP388 wallet on node 1, this is a 2-of-2 MuSig2.
        device_a = self._make_device_cosigner('hww_musig_device_a')
        device_b = self._make_device_cosigner('hww_musig_device_b')

        # Wire the mock to enumerate two devices and route each
        # fingerprint to its own cosigner wallet.
        with open(os.path.join(cwd, 'mock_fingerprints'), 'w') as f:
            f.write(f"{device_a['fingerprint']},{device_b['fingerprint']}")
        self._set_musig_signtx_delegate('hww_musig_device_a',
                                        fingerprint=device_a['fingerprint'])
        self._set_musig_signtx_delegate('hww_musig_device_b',
                                        fingerprint=device_b['fingerprint'])

        # BIP388 wallet on node 1: no local privkeys (both cosigners are
        # devices), blank so signer setup doesn't auto-import single-sig
        # placeholder descriptors.
        self.nodes[1].createwallet(
            wallet_name='hww_bip388_2of2',
            disable_private_keys=True,
            external_signer=True,
            blank=True,
        )
        hww = self.nodes[1].get_wallet_rpc('hww_bip388_2of2')
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
        # device's own xprv swapped in. The mock delegates signtx to
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

        # registerpolicy fans out: one bip388 record per device.
        self._set_musig_registerpolicy_nohmac(True)
        hww.registerpolicy()
        info = hww.getwalletinfo()
        assert_equal(len(info["bip388"]), 2)
        assert_equal({entry["fingerprint"] for entry in info["bip388"]},
                     {device_a['fingerprint'], device_b['fingerprint']})

        # Fund the aggregated address.
        addr = hww.getnewaddress(address_type="bech32m")
        self.def_wallet.sendtoaddress(addr, 1)
        self.generate(self.nodes[0], 1)

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
        # FillPSBTPolicy short-circuits the remaining signers. So one
        # device sees two signtx calls and the other sees one.
        counters = sorted(
            int(open(os.path.join(cwd, f"mock_signtx_{d['fingerprint']}_counter")).read())
            for d in (device_a, device_b)
        )
        assert_equal(counters, [1, 2])
        assert self.nodes[0].testmempoolaccept([proc["hex"]])[0]["allowed"]

    def _make_device_cosigner(self, name):
        """Stand up a cosigner wallet on node 0 to back one mock device.
        Returns a dict with the wallet handle and the BIP32 material the
        BIP388 wallet's MuSig2 descriptor needs."""
        self.nodes[0].createwallet(wallet_name=name)
        wallet = self.nodes[0].get_wallet_rpc(name)
        wallet.addhdkey()
        info = wallet.derivehdkey(DEVICE_ACCOUNT_PATH, {"private": True})
        return {
            'wallet': wallet,
            'origin': info["origin"],
            'xpub': info["xpub"],
            'xprv': info["xprv"],
            'fingerprint': info["origin"][1:9],
        }


if __name__ == '__main__':
    WalletSignerMuSig2Test(__file__).main()

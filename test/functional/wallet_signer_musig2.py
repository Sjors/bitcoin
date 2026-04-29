#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test MuSig2 descriptors in an external-signer wallet."""
import os
import re

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


# The device side of the MuSig2 setup.
DEVICE_ORIGIN = "[00000001/84h/1h/0h]"
DEVICE_XPUB = "tpubDCxzhZZE31g2EqSv1UajMAw5Hd62htydz9r2XBkrccHgBh8uw3n62zr6Zjmj64tfTk8Tjxo6VctjUMAh5DXWTErfQPC6RmQhTdtNnXuTXTQ"

# Hardcode the local MuSig participant's account xprv so the test can import a
# descriptor with one hot-wallet key and one external-signer key.
LOCAL_ORIGIN = "[ec63add0/84h/1h/0h]"
LOCAL_XPRV = "tprv8gauGKtmnH4cxv22ZtmEKqDDAeqnm2b4srPWuFsugMuVc79KDEHRTWgKGdAhACqjZQytU1o9gcc91TSW8L1s18PgFUHAJ8p8iY1GwaUEn9u"

# The hot wallet in this test does not contain an HD key. After
# bitcoin/bitcoin#29136 it could, and after bitcoin/bitcoin#32784 we could
# derive the 84h/1h/0h derivation xprv. A subsequent improvement to
# importdescriptors could avoid the need to handle xprvs, by recognizing
# an xpub for which it already has the matching private key material.

class WalletSignerMuSig2Test(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [
            [],
            [f"-signer={self.mock_signer_path()}", '-keypool=10'],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_external_signer()
        self.skip_if_no_wallet()

    def run_test(self):
        self.test_create_wallet()
        self.test_display_address()
        # Unload the hot wallet so its name doesn't collide with the BIP388
        # wallet created below (and so it isn't carried across the restart).
        self.nodes[1].unloadwallet('hww_musig')
        self.restart_node(1, [f"-signer={self.mock_signer_path('signer_musig.py')}", "-keypool=10"])
        self.test_bip388_musig2_policy()

    def test_create_wallet(self):
        self.log.info('Create an external-signer wallet with a MuSig2 descriptor')

        musig_descriptor = f"tr(musig({LOCAL_ORIGIN}{LOCAL_XPRV},{DEVICE_ORIGIN}{DEVICE_XPUB})/<0;1>/*)"

        # Blank wallet so createwallet doesn't import the device's single-sig
        # descriptors (which would clutter the wallet).
        self.nodes[1].createwallet(
            wallet_name='hww_musig',
            external_signer=True,
            disable_private_keys=False,
            blank=True,
        )
        hww_musig = self.nodes[1].get_wallet_rpc('hww_musig')

        result = hww_musig.importdescriptors([{
            "desc": descsum_create(musig_descriptor),
            "active": True,
            "timestamp": "now",
        }])
        assert_equal(result[0]["success"], True)

        # Reload so the imported descriptor is managed by
        # ExternalSignerScriptPubKeyMan rather than the plain
        # DescriptorScriptPubKeyMan it was added to on import.
        self.nodes[1].unloadwallet('hww_musig')
        self.nodes[1].loadwallet('hww_musig')

        descs = self.nodes[1].get_wallet_rpc('hww_musig').listdescriptors()["descriptors"]
        active_musig = [d for d in descs if d["active"] and d["desc"].startswith("tr(musig(")]
        # One active descriptor each for receive and change.
        assert_equal(len(active_musig), 2)

    def test_display_address(self):
        self.log.info('Display an address from the MuSig2 descriptor')
        hww_musig = self.nodes[1].get_wallet_rpc('hww_musig')

        addr = hww_musig.getnewaddress(address_type="bech32m")
        addr_info = hww_musig.getaddressinfo(addr)
        assert_equal(addr_info["ismine"], True)
        assert_equal(addr_info["solvable"], True)
        # This is not expected to work on a real device, which needs additional
        # information such as a BIP388 policy.
        assert_equal(hww_musig.walletdisplayaddress(addr), {"address": addr})

    def _make_musig2_descriptor(self):
        """Build a `tr(musig(...))` MuSig2 descriptor and import it into two
        regular cosigner wallets on node 0. Returns the cosigner wallet
        handles and the xpub-only form of the descriptor (suitable for
        importing into a BIP388 wallet that has no private keys)."""
        privkey_re = re.compile(r"^tr\((.+?)/.+\)#.{8}$")
        pubkey_re = re.compile(r"^tr\((\[.+?\].+?)/.+\)#.{8}$")
        origin_path_re = re.compile(r"^\[\w{8}(/.*)\].*$")
        privkeys = []
        pubkeys = []
        for label in ("musig_addr_a", "musig_addr_b"):
            self.nodes[0].createwallet(wallet_name=label)
            w = self.nodes[0].get_wallet_rpc(label)
            priv = None
            for d in w.listdescriptors(True)["descriptors"]:
                if d["desc"].startswith("tr("):
                    priv = privkey_re.search(d["desc"]).group(1)
                    break
            assert priv is not None, "no tr() privkey descriptor found"
            pub = None
            for d in w.listdescriptors()["descriptors"]:
                if d["desc"].startswith("tr("):
                    pub = pubkey_re.search(d["desc"]).group(1)
                    break
            assert pub is not None, "no tr() pubkey descriptor found"
            # The bare xprv is at depth 0; the pub form's origin path
            # tells us which child the descriptor expects at depth 0.
            # Append the origin path to the xprv so both forms derive
            # the same key (same trick as wallet_musig.py).
            priv += origin_path_re.search(pub).group(1)
            privkeys.append(priv)
            pubkeys.append(pub)

        a, b = (self.nodes[0].get_wallet_rpc(n) for n in ("musig_addr_a", "musig_addr_b"))
        descs = {
            a: f"tr(musig({privkeys[0]}/<0;1>/*,{pubkeys[1]}/<0;1>/*))",
            b: f"tr(musig({pubkeys[0]}/<0;1>/*,{privkeys[1]}/<0;1>/*))",
        }
        for w, d in descs.items():
            res = w.importdescriptors([{
                "desc": descsum_create(d),
                "active": True,
                "timestamp": "now",
            }])
            assert_equal(res[0]["success"], True)

        desc_xpub_only = f"tr(musig({pubkeys[0]}/<0;1>/*,{pubkeys[1]}/<0;1>/*))"
        return a, b, desc_xpub_only

    def test_bip388_musig2_policy(self):
        self.log.info("Test BIP388 MuSig2 policy displayaddress via mock signer")
        # Build a 2-of-2 MuSig2 descriptor using two cosigner wallets on
        # node 0; the BIP388 wallet on node 1 will import the xpub-only
        # form via the mock signer's getdescriptors response.
        a, _b, desc_xpub_only = self._make_musig2_descriptor()

        # Stage the BECH32M descriptors the mock will return from
        # `getdescriptors`. createwallet(external_signer=True) calls
        # SetupDescriptorScriptPubKeyMans which auto-imports the
        # advertised descriptors as ExternalSignerScriptPubKeyMan -- the
        # only SPKM kind that the BIP388 dispatch in CWallet recognises.
        # The fingerprint just has to match the BIP388 entry the wallet
        # stores after registerpolicy; it does NOT need to be one of the
        # MuSig2 cosigner fingerprints.
        device_fp = "deadbeef"
        cwd = self.nodes[1].cwd
        with open(os.path.join(cwd, 'mock_fingerprint'), 'w') as f:
            f.write(device_fp)
        with open(os.path.join(cwd, 'mock_getdescriptors_bech32m_receive'), 'w') as f:
            f.write(descsum_create(desc_xpub_only.replace('<0;1>', '0')))
        with open(os.path.join(cwd, 'mock_getdescriptors_bech32m_internal'), 'w') as f:
            f.write(descsum_create(desc_xpub_only.replace('<0;1>', '1')))

        # BIP388 wallet on node 1: external_signer=True, disable_private_keys=True.
        self.nodes[1].createwallet(
            wallet_name='hww_bip388',
            disable_private_keys=True,
            external_signer=True,
        )
        hww = self.nodes[1].get_wallet_rpc('hww_bip388')

        # Register the policy so CWallet::DisplayAddress dispatches into
        # DisplayAddressPolicy (matched on fingerprint).
        reg = hww.registerpolicy()
        assert_equal(reg["hmac"], "00" * 32)
        info = hww.getwalletinfo()
        assert_equal(info["bip388"][0]["hmac"], "00" * 32)
        assert_equal(info["bip388"][0]["name"], "hww_bip388")
        assert_equal(info["bip388"][0]["fingerprint"], device_fp)

        # First receive-chain MuSig2 address; the cosigner wallet derives
        # the same key at index 0, which lets the test cross-check.
        display_addr = hww.getnewaddress(address_type="bech32m")
        assert_equal(display_addr, a.getnewaddress(address_type="bech32m"))

        mock_display_path = os.path.join(cwd, "mock_displayaddress")
        with open(mock_display_path, "w") as f:
            f.write(display_addr)
        # CWallet::DisplayAddress should dispatch through the BIP388
        # DisplayAddressPolicy path (rather than the single-key
        # InferDescriptor path) and the device echo must round-trip.
        assert_equal(hww.walletdisplayaddress(display_addr), {"address": display_addr})

        # If the device echoes a different address the wallet must error.
        with open(mock_display_path, "w") as f:
            f.write("bcrt1qm90ugl4d48jv8n6e5t9ln6t9zlpm5th68x4f8g")
        assert_raises_rpc_error(-1, "Signer echoed unexpected address",
            hww.walletdisplayaddress, display_addr,
        )
        os.remove(mock_display_path)


if __name__ == '__main__':
    WalletSignerMuSig2Test(__file__).main()

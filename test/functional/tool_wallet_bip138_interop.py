#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Interoperability test between Bitcoin Core's BIP138 encrypted backups and
the bip138-rs reference implementation (https://github.com/pythcoiner/bip138).

This test is a developer tool, not part of CI. It drives both CLIs:
- bitcoin-wallet encryptbackup / decryptbackup / inspectbackup (base64 I/O)
- beb encrypt / decrypt / inspect (raw binary file I/O)

Build the Rust CLI first:
    cd ~/bip138-rs && cargo build --release --features cli

Then run:
    BEB=~/bip138-rs/target/release/beb \
        test/functional/tool_wallet_bip138_interop.py \
        --configfile=<builddir>/test/config.ini

Known divergence this test documents (see test_wrapped_backup):
- bip138-rs supports multi-level key wrapping (nested backups carried as
  BIP-number-138 content items, not part of the BIP); Core only extracts
  BIP380 content items, so it cannot unwrap the outer layer and fails
  cleanly. It can decrypt the inner backup once another tool unwraps the
  outer level.
"""

import base64
import json
import os
import re
import subprocess

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import (
    assert_equal,
)

BEB = os.getenv("BEB")

# An unrelated testnet xpub, used as a wrong decryption key.
UNRELATED_XPUB = "tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp"


def norm_desc(desc):
    """Normalize a descriptor string for comparison: strip the checksum and
    use 'h' as the hardened marker (Core prints h, rust-miniscript prints ')."""
    return desc.split("#")[0].replace("'", "h")


def expand_multipath(desc):
    """Expand a /<0;1>/ multipath descriptor into its receive and change form."""
    if "<0;1>" not in desc:
        return [desc]
    return [desc.replace("<0;1>", "0"), desc.replace("<0;1>", "1")]


def doc_descs(doc):
    """Normalized single-path descriptors of a descriptor backup document.
    A set carries either a multipath descriptor or a receive/change pair."""
    descs = []
    for s in doc["descriptor_sets"]:
        for d in [s["descriptor"]] + ([s["change_descriptor"]] if s.get("change_descriptor") else []):
            descs.extend(expand_multipath(norm_desc(d)))
    return sorted(descs)


class ToolWalletBip138InteropTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_wallet_tool()
        if not BEB:
            raise SkipTest("BEB env var not set (path to beb binary from bip138-rs)")

    # --- helpers -----------------------------------------------------------

    def bitcoin_wallet(self, *args, stdin=None, expect_code=0, expect_err=None):
        """Run bitcoin-wallet, return stdout. Asserts on exit code, and on
        stderr content when expect_err is given."""
        default_args = [f"-datadir={self.nodes[0].datadir_path}", f"-chain={self.chain}"]
        p = subprocess.Popen(self.get_binaries().wallet_argv() + default_args + list(args),
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = p.communicate(input=stdin)
        assert_equal(p.poll(), expect_code)
        if expect_err is not None:
            assert expect_err in stderr, f"expected {expect_err!r} in stderr, got: {stderr!r}"
        elif expect_code == 0:
            assert_equal(stderr, "")
        return stdout

    def beb(self, *args, expect_code=0, expect_err=None):
        """Run the beb CLI, return stdout as bytes. Asserts on exit code, and
        on stderr content when expect_err is given."""
        p = subprocess.Popen([BEB] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        stderr = stderr.decode(errors="replace")
        assert p.poll() == expect_code, f"beb {' '.join(args)}: exit {p.poll()}, stderr: {stderr}"
        if expect_err is not None:
            # beb reports errors on stdout ("Error: ...") in some paths and
            # stderr in others; accept either.
            combined = stderr + stdout.decode(errors="replace")
            assert expect_err in combined, f"expected {expect_err!r}, got: {combined!r}"
        return stdout

    def tmp_file(self, name, data=None):
        path = os.path.join(self.options.tmpdir, name)
        if data is not None:
            mode = "wb" if isinstance(data, bytes) else "w"
            with open(path, mode) as f:
                f.write(data)
        return path

    def core_backup_to_file(self, backup_base64, name):
        """Decode a Core base64 backup into the raw binary file format beb reads."""
        raw = base64.b64decode(backup_base64)
        assert_equal(raw[:6], b"BIP138")
        return self.tmp_file(name, raw)

    def beb_backup_to_base64(self, path):
        """Encode a beb binary backup as the base64 Core reads."""
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode()

    def beb_inspect(self, path):
        return json.loads(self.beb("inspect", "-f", path).decode())

    def beb_decrypt(self, backup_path, xpub, out_name, expect_code=0, expect_err=None):
        """Decrypt a binary backup with a bare xpub, return the decrypted document text."""
        key_file = self.tmp_file("beb_key.txt", xpub + "\n")
        out_path = self.tmp_file(out_name)
        if os.path.exists(out_path):
            os.unlink(out_path)
        self.beb("decrypt", "-f", backup_path, "-k", key_file, "-o", out_path,
                 expect_code=expect_code, expect_err=expect_err)
        if expect_code != 0:
            return None
        with open(out_path) as f:
            return f.read().strip()

    def core_inspect(self, backup_base64):
        return json.loads(self.bitcoin_wallet("inspectbackup", stdin=backup_base64))

    def core_encryptbackup(self, wallet_name, *args):
        return self.bitcoin_wallet(f"-wallet={wallet_name}", *args, "encryptbackup").strip()

    def core_decryptbackup(self, backup_base64, xpub):
        return self.bitcoin_wallet(f"-pubkey={xpub}", "decryptbackup", stdin=backup_base64).strip()

    # --- setup -------------------------------------------------------------

    def harvest_origin_key(self, wallet, purpose):
        """Return ([fingerprint/path]tpub..., tpub...) for the account-level key of
        the wallet's receive descriptor with the given purpose (e.g. "84h")."""
        for d in wallet.listdescriptors()["descriptors"]:
            m = re.search(r"\[([0-9a-f]{8}/[0-9h/]+)\](tpub[A-Za-z0-9]+)", d["desc"])
            if m and f"/{purpose}/" in f"/{m.group(1).split('/', 1)[1]}/" and not d["internal"]:
                return f"[{m.group(1)}]{m.group(2)}", m.group(2)
        raise AssertionError(f"no {purpose} descriptor in wallet")

    def setup_wallets(self):
        """Create all wallets and harvest key material while the node runs."""
        node = self.nodes[0]

        # A default single-sig wallet, the plain-vanilla backup subject.
        node.createwallet("single")
        single = node.get_wallet_rpc("single")
        self.single_descs = sorted(norm_desc(d["desc"]) for d in single.listdescriptors()["descriptors"])
        # The encryption key set comes from the backup's primary descriptor:
        # the lexicographically first receive descriptor (pkh, purpose 44h).
        # Its account-level xpub is the decryption key.
        first_desc = sorted(d["desc"] for d in single.listdescriptors()["descriptors"])[0]
        m = re.search(r"\](tpub[A-Za-z0-9]+)", first_desc)
        assert m, f"no origin xpub in {first_desc}"
        self.single_xpub = m.group(1)

        # Three cosigner wallets: harvest their 84h account keys for a multisig.
        self.cosigner_keys = []  # ([origin]tpub, tpub) pairs
        for i in range(3):
            node.createwallet(f"cosigner{i}")
            self.cosigner_keys.append(self.harvest_origin_key(node.get_wallet_rpc(f"cosigner{i}"), "84h"))

        # The PR's target use case: a wallet with a single multisig descriptor
        # (receive/change pair from one multipath import).
        key_exprs = ",".join(f"{origin}/<0;1>/*" for origin, _ in self.cosigner_keys)
        self.ms_desc = f"wsh(sortedmulti(2,{key_exprs}))"
        node.createwallet("ms", disable_private_keys=True, blank=True)
        ms = node.get_wallet_rpc("ms")
        res = ms.importdescriptors([{"desc": descsum_create(self.ms_desc), "timestamp": "now", "range": 10}])
        assert all(r["success"] for r in res), res
        self.ms_descs = sorted(norm_desc(d["desc"]) for d in ms.listdescriptors()["descriptors"])

        # Same multisig but with an uncommon origin path (account 10 is outside
        # the common-path list), so a -xpub targeted backup must carry a
        # derivation path hint in the header.
        uncommon_exprs = ",".join(
            f"[{origin.split('/', 1)[0].lstrip('[')}/48h/1h/10h/2h]{tpub}/<0;1>/*"
            for origin, tpub in self.cosigner_keys)
        self.ms_uncommon_desc = f"wsh(sortedmulti(2,{uncommon_exprs}))"
        node.createwallet("ms_uncommon", disable_private_keys=True, blank=True)
        ms_u = node.get_wallet_rpc("ms_uncommon")
        res = ms_u.importdescriptors([{"desc": descsum_create(self.ms_uncommon_desc), "timestamp": "now", "range": 10}])
        assert all(r["success"] for r in res), res

        # Empty watch-only wallet, target of the Rust->Core restore.
        node.createwallet("restore", disable_private_keys=True, blank=True)

    # --- test cases --------------------------------------------------------

    def test_full_backup_core_to_beb(self):
        self.log.info("Core full backup -> beb inspect/decrypt")
        b64 = self.core_encryptbackup("single")
        bin_path = self.core_backup_to_file(b64, "single_full.bin")

        # Metadata agreement between the two inspect commands
        core_meta = self.core_inspect(b64)
        beb_meta = self.beb_inspect(bin_path)
        assert_equal(core_meta["version"], 1)
        assert_equal(beb_meta["version"], "V1")
        # One real recipient padded with decoys to the smallest bucket
        assert_equal(core_meta["individual_secrets"], 5)
        assert_equal(len(beb_meta["individual_secrets"]), 5)
        assert_equal(beb_meta["encryption"], "ChaCha20Poly1305")
        assert_equal(core_meta["derivation_paths"], [])
        assert_equal(beb_meta["derivation_paths"], [])

        # beb decrypts the JSON descriptor backup document with the account xpub
        doc_text = self.beb_decrypt(bin_path, self.single_xpub, "single_full.json")
        doc = json.loads(doc_text)
        assert_equal(doc["version"], 1)
        assert_equal(len(doc["descriptor_sets"]), 4)

        # The decrypted descriptor sets expand to exactly the wallet's
        # listdescriptors set.
        assert_equal(doc_descs(doc), self.single_descs)

        # Core's own plaintext parses to the same document
        core_doc = json.loads(self.core_decryptbackup(b64, self.single_xpub))
        assert_equal(doc_descs(doc), doc_descs(core_doc))

        # A key that is not a recipient fails cleanly
        self.beb_decrypt(bin_path, UNRELATED_XPUB, "unused.txt", expect_code=1, expect_err="WrongKey")

    def test_compact_backup_core_to_beb(self):
        self.log.info("Core compact backup -> beb")
        # A compact backup holds a single bare descriptor (per the BIP380
        # content definition), so a multi-descriptor-set wallet is refused
        self.bitcoin_wallet("-wallet=single", "-compact", "encryptbackup",
                            expect_code=1, expect_err="single descriptor set")

        # Single-descriptor-set wallet: one bare multipath descriptor item
        ms_b64 = self.core_encryptbackup("ms", "-compact")
        ms_bin = self.core_backup_to_file(ms_b64, "ms_compact.bin")

        # Compact backups skip decoy padding: only the real secrets remain,
        # one per cosigner
        assert_equal(self.core_inspect(ms_b64)["individual_secrets"], len(self.cosigner_keys))
        assert_equal(len(self.beb_inspect(ms_bin)["individual_secrets"]), len(self.cosigner_keys))

        ms_plain = self.core_decryptbackup(ms_b64, self.cosigner_keys[0][1])
        assert_equal(norm_desc(ms_plain), norm_desc(self.ms_desc))
        ms_text = self.beb_decrypt(ms_bin, self.cosigner_keys[0][1], "ms_compact.txt")
        assert_equal(norm_desc(ms_text), norm_desc(self.ms_desc))

    def test_multisig_backup_each_cosigner(self):
        self.log.info("Core multisig backup -> every cosigner key decrypts, on both implementations")
        self.ms_backup_b64 = self.core_encryptbackup("ms")
        bin_path = self.core_backup_to_file(self.ms_backup_b64, "ms_full.bin")

        expected = sorted(self.ms_descs)
        for i, (_, tpub) in enumerate(self.cosigner_keys):
            # beb
            doc = json.loads(self.beb_decrypt(bin_path, tpub, f"ms_full_{i}.json"))
            assert_equal(doc_descs(doc), expected)
            # Core
            core_doc = json.loads(self.core_decryptbackup(self.ms_backup_b64, tpub))
            assert_equal(doc_descs(core_doc), expected)

        # A non-cosigner key fails on both
        self.beb_decrypt(bin_path, self.single_xpub, "unused.txt", expect_code=1, expect_err="WrongKey")
        self.bitcoin_wallet(f"-pubkey={self.single_xpub}", "decryptbackup", stdin=self.ms_backup_b64,
                            expect_code=1, expect_err="does not match any recipient")

    def test_xpub_target_derivation_path(self):
        self.log.info("Core -xpub targeted backup carries a derivation path hint beb can read")
        target_tpub = self.cosigner_keys[0][1]
        b64 = self.core_encryptbackup("ms_uncommon", f"-xpub={target_tpub}")
        bin_path = self.core_backup_to_file(b64, "ms_uncommon.bin")

        core_meta = self.core_inspect(b64)
        beb_meta = self.beb_inspect(bin_path)
        assert_equal(len(core_meta["derivation_paths"]), 1)
        assert_equal(len(beb_meta["derivation_paths"]), 1)
        # Same path, modulo hardened marker formatting
        core_path = core_meta["derivation_paths"][0].replace("'", "h").removeprefix("m/")
        beb_path = str(beb_meta["derivation_paths"][0]).replace("'", "h").removeprefix("m/")
        assert_equal(core_path, "48h/1h/10h/2h")
        assert_equal(beb_path, core_path)

        # The targeted key decrypts
        doc = json.loads(self.beb_decrypt(bin_path, target_tpub, "ms_uncommon.json"))
        assert norm_desc(self.ms_uncommon_desc).replace("<0;1>", "0") in doc_descs(doc)

    def test_beb_to_core(self):
        self.log.info("beb encrypt -> Core decrypt and wallet restore")
        desc_file = self.tmp_file("ms_desc.txt", self.ms_desc)
        keys_file = self.tmp_file("ms_keys.txt", " | ".join(origin for origin, _ in self.cosigner_keys) + "\n")
        backup_path = self.tmp_file("beb_ms.bin")
        if os.path.exists(backup_path):
            os.unlink(backup_path)
        self.beb("encrypt", "-f", desc_file, "--keys", keys_file, "-o", backup_path)
        b64 = self.beb_backup_to_base64(backup_path)

        # Core can inspect it
        meta = self.core_inspect(b64)
        assert_equal(meta["version"], 1)

        # Every cosigner key decrypts it with Core
        for _, tpub in self.cosigner_keys:
            plaintext = self.core_decryptbackup(b64, tpub)
            assert_equal(norm_desc(plaintext), norm_desc(self.ms_desc))

        # And Core can restore a wallet from it
        self.bitcoin_wallet("-wallet=restore", f"-pubkey={self.cosigner_keys[0][1]}",
                            "decryptbackup", stdin=b64)

    def test_msg_note(self):
        self.log.info("beb --msg note backup -> Core still extracts the descriptor")
        desc_file = self.tmp_file("ms_desc.txt", self.ms_desc)
        keys_file = self.tmp_file("ms_keys.txt", " | ".join(origin for origin, _ in self.cosigner_keys) + "\n")
        backup_path = self.tmp_file("beb_msg.bin")
        if os.path.exists(backup_path):
            os.unlink(backup_path)
        self.beb("encrypt", "-f", desc_file, "--keys", keys_file, "--msg", "note for future me", "-o", backup_path)
        plaintext = self.core_decryptbackup(self.beb_backup_to_base64(backup_path), self.cosigner_keys[0][1])
        # Core selects the BIP380 content item; the note (a separate string
        # content item) is not part of the output.
        assert_equal(norm_desc(plaintext), norm_desc(self.ms_desc))

    def test_wrapped_backup(self):
        self.log.info("beb two-level wrapped backup -> Core cannot unwrap (documented divergence)")
        desc_file = self.tmp_file("ms_desc.txt", self.ms_desc)
        # Outer level: cosigner 0. Inner level: all three cosigners.
        keys_file = self.tmp_file("wrap_keys.txt",
                                  self.cosigner_keys[0][0] + "\n" +
                                  " | ".join(origin for origin, _ in self.cosigner_keys) + "\n")
        backup_path = self.tmp_file("beb_wrapped.bin")
        if os.path.exists(backup_path):
            os.unlink(backup_path)
        self.beb("encrypt", "-f", desc_file, "--keys", keys_file, "-o", backup_path)
        b64 = self.beb_backup_to_base64(backup_path)

        # Each wrap level is an ordinary BIP138 backup whose payload is a
        # content item of type BIP number 138 holding the next backup, with
        # ordinary recipients. Core's decryptbackup only extracts BIP380
        # content items, so it cannot unwrap the outer layer even though its
        # key does decrypt it. It must fail cleanly, reporting the missing
        # descriptor content rather than a key mismatch.
        self.bitcoin_wallet(f"-pubkey={self.cosigner_keys[0][1]}", "decryptbackup", stdin=b64,
                            expect_code=1, expect_err="contains no descriptor")

        # One-level-at-a-time recovery works across implementations: beb
        # unwraps the outer layer, and Core decrypts the inner backup.
        inner_path = self.tmp_file("beb_inner.bin")
        if os.path.exists(inner_path):
            os.unlink(inner_path)
        key_file = self.tmp_file("beb_key.txt", self.cosigner_keys[0][1] + "\n")
        self.beb("decrypt", "-f", backup_path, "-k", key_file, "-o", inner_path)
        with open(inner_path, "rb") as f:
            inner = f.read().rstrip(b"\n")  # beb appends a trailing newline to documents
        assert_equal(inner[:6], b"BIP138")
        inner_b64 = base64.b64encode(inner).decode()
        assert_equal(self.core_inspect(inner_b64)["version"], 1)
        plaintext = self.core_decryptbackup(inner_b64, self.cosigner_keys[0][1])
        assert_equal(norm_desc(plaintext), norm_desc(self.ms_desc))

    def test_malformed_backups(self):
        self.log.info("Tampered and zero-nonce backups are rejected by both")
        raw = base64.b64decode(self.ms_backup_b64)

        # Flip the last byte (inside the AEAD tag)
        tampered = raw[:-1] + bytes([raw[-1] ^ 0x01])
        tampered_b64 = base64.b64encode(tampered).decode()
        tampered_path = self.tmp_file("tampered.bin", tampered)
        self.bitcoin_wallet(f"-pubkey={self.cosigner_keys[0][1]}", "decryptbackup", stdin=tampered_b64,
                            expect_code=1, expect_err="")
        self.beb_decrypt(tampered_path, self.cosigner_keys[0][1], "unused.txt",
                         expect_code=1, expect_err="WrongKey")

        # Zero out the nonce (located via beb inspect)
        nonce = bytes.fromhex(self.beb_inspect(self.core_backup_to_file(self.ms_backup_b64, "ms_full.bin"))["nonce"])
        i = raw.index(nonce)
        zeroed = raw[:i] + b"\x00" * 12 + raw[i + 12:]
        zeroed_b64 = base64.b64encode(zeroed).decode()
        zeroed_path = self.tmp_file("zerononce.bin", zeroed)
        self.bitcoin_wallet("inspectbackup", stdin=zeroed_b64,
                            expect_code=1, expect_err="Invalid all-zero nonce")
        self.beb_decrypt(zeroed_path, self.cosigner_keys[0][1], "unused.txt",
                         expect_code=1, expect_err="ZeroedNonce")

    def verify_restore(self):
        """Back up: the restored wallet holds the same descriptors as the original."""
        self.log.info("Restored wallet matches the original multisig wallet")
        node = self.nodes[0]
        node.loadwallet("restore")
        restored = sorted(norm_desc(d["desc"]) for d in node.get_wallet_rpc("restore").listdescriptors()["descriptors"])
        assert_equal(restored, self.ms_descs)

    def run_test(self):
        self.log.info(f"Using beb binary: {BEB}")
        self.setup_wallets()

        # bitcoin-wallet needs exclusive access to the wallet directory
        self.stop_node(0)

        self.test_full_backup_core_to_beb()
        self.test_compact_backup_core_to_beb()
        self.test_multisig_backup_each_cosigner()
        self.test_xpub_target_derivation_path()
        self.test_beb_to_core()
        self.test_msg_note()
        self.test_wrapped_backup()
        self.test_malformed_backups()

        self.start_node(0)
        self.verify_restore()


if __name__ == '__main__':
    ToolWalletBip138InteropTest(__file__).main()

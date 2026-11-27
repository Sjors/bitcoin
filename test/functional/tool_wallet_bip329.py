#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test bitcoin-wallet BIP329 label import and export."""

import json
import subprocess
import textwrap
from datetime import datetime, timezone
from decimal import Decimal

from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


BIP329_TEST_VECTORS = [
    {
        "type": "tx",
        "ref": "f91d0a8a78462bc59398f2c5d7a84fcff491c26ba54c4833478b202796c8aafd",
        "label": "Transaction",
        "origin": "wpkh([d34db33f/84'/0'/0'])",
    },
    {
        "type": "addr",
        "ref": "bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c",
        "label": "Address",
    },
    {
        "type": "pubkey",
        "ref": "0283409659355b6d1cc3c32decd5d561abaac86c37a353b52895a5e6c196d6f448",
        "label": "Public Key",
    },
    {
        "type": "input",
        "ref": "f91d0a8a78462bc59398f2c5d7a84fcff491c26ba54c4833478b202796c8aafd:0",
        "label": "Input",
    },
    {
        "type": "output",
        "ref": "f91d0a8a78462bc59398f2c5d7a84fcff491c26ba54c4833478b202796c8aafd:1",
        "label": "Output",
        "spendable": False,
    },
    {
        "type": "xpub",
        "ref": "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        "label": "Extended Public Key",
    },
    {
        "type": "spscan",
        "ref": "spscan1q5zs2pg9q5zs2pg9q5zs2pg9q5zs2pg9q5zsq9q6qjevn2kmdrnpuxt0v6h2kr2a2epkr0g6nk55ftf0xcxtddazgkrth3e",
        "label": "Silent Payments Scan Key Expression",
    },
    {
        "type": "tx",
        "ref": "f546156d9044844e02b181026a1a407abfca62e7ea1159f87bbeaa77b4286c74",
        "label": "Account #1 Transaction",
        "origin": "wpkh([d34db33f/84'/0'/1'])",
    },
]

# BIP329 vector coverage:
# - addr label: imported and exported.
# - output spendable=false: imported and exported as a persistent locked coin.
# - tx labels: imported records are omitted because Bitcoin Core stores send
#   comments, not arbitrary transaction labels that can be applied to any wallet
#   transaction. Wallet transactions are now exported as accounting records.
# - input, pubkey, xpub, and spscan labels: omitted because Bitcoin Core wallets
#   do not store labels for these record types.
# - imported output labels without a spendable field are omitted because Bitcoin
#   Core can persist output locks, but not labels attached to individual outputs.
#
# Bitcoin Core wallet metadata not represented by BIP329 and intentionally not
# covered by this label round-trip: address purpose (receive/send/refund),
# change-address marker, receive-request data, avoid-reuse previously-spent
# marker, transaction order/state/conflicts, keys, keypool, wallet flags,
# encryption state, and database settings.


class ToolWalletBIP329Test(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_wallet_tool()

    def bitcoin_wallet_process(self, *args, chain=None):
        default_args = [
            f"-datadir={self.nodes[0].datadir_path}",
            "-chain=%s" % (chain or self.chain),
        ]
        return subprocess.Popen(
            self.get_binaries().wallet_argv() + default_args + list(args),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def run_wallet_tool(self, *args, chain=None):
        p = self.bitcoin_wallet_process(*args, chain=chain)
        stdout, stderr = p.communicate()
        assert_equal(stderr, "")
        assert_equal(p.poll(), 0)
        return stdout

    def assert_tool_output(self, output, *args, chain=None):
        assert_equal(self.run_wallet_tool(*args, chain=chain), output)

    def get_expected_info_output(self, name, keypool=2):
        output_types = 4  # p2pkh, p2sh, segwit, bech32m
        return textwrap.dedent("""\
            Wallet info
            ===========
            Name: %s
            Format: sqlite
            Descriptors: yes
            Encrypted: no
            HD (hd seed available): yes
            Keypool Size: %d
            Transactions: 0
            Address Book: 0
        """ % (name, keypool * output_types))

    def read_jsonl(self, filename):
        with open(filename, "r", encoding="utf8") as f:
            return [json.loads(line) for line in f]

    def write_jsonl(self, records, filename):
        with open(filename, "w", encoding="utf8") as f:
            for record in records:
                f.write(json.dumps(record, separators=(",", ":")) + "\n")

    def importable_records(self, records):
        return [
            record for record in records
            if record["type"] == "addr" or (record["type"] == "output" and "spendable" in record)
        ]

    def isoformat(self, timestamp):
        return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def sats(self, amount):
        return int(amount * Decimal(COIN))

    def test_bip329_vectors(self):
        self.log.info("Test BIP329 import/export against the specification vectors")

        wallet_name = "bip329_vectors"
        vector_file = self.nodes[0].datadir_path / "bip329_vectors.jsonl"
        vector_export = self.nodes[0].datadir_path / "bip329_vectors_export.jsonl"
        self.write_jsonl(BIP329_TEST_VECTORS, vector_file)

        self.assert_tool_output(
            "Topping up keypool...\n" + self.get_expected_info_output(name=wallet_name, keypool=2000),
            f"-wallet={wallet_name}",
            "create",
            chain="main",
        )
        self.assert_tool_output(
            f"Imported 2 BIP329 records from {vector_file}; ignored 6 unsupported records\n",
            f"-wallet={wallet_name}",
            f"-labelsfile={vector_file}",
            "importlabels",
            chain="main",
        )
        stdout = self.run_wallet_tool(
            f"-wallet={wallet_name}",
            f"-labelsfile={vector_export}",
            "exportlabels",
            chain="main",
        )
        exported_records = self.read_jsonl(vector_export)
        assert_equal(stdout, f"Exported {len(exported_records)} BIP329 records to {vector_export}\n")
        assert_equal(
            sorted(self.importable_records(exported_records), key=lambda record: (record["type"], record["ref"])),
            [
                {"type": "addr", "ref": "bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c", "label": "Address"},
                {
                    "type": "output",
                    "ref": "f91d0a8a78462bc59398f2c5d7a84fcff491c26ba54c4833478b202796c8aafd:1",
                    "spendable": False,
                },
            ],
        )
        assert_equal(len([record for record in exported_records if record["type"] == "descriptor"]), 8)

    def test_wallet_roundtrip(self):
        self.log.info("Test BIP329 round-trip for Bitcoin Core wallet metadata")

        self.nodes[0].createwallet("bip329_source")
        source = self.nodes[0].get_wallet_rpc("bip329_source")
        default_wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        receive_address = source.getnewaddress("receive label")
        external_address = default_wallet.getnewaddress()
        source.setlabel(external_address, "send label")

        self.generate(self.nodes[0], 101)
        receive_txid = default_wallet.sendtoaddress(receive_address, 1)
        self.generate(self.nodes[0], 6)
        receive_entry = next(entry for entry in source.listtransactions("*", 100) if entry["txid"] == receive_txid)
        locked_output = source.listunspent()[0]
        source.lockunspent(False, [{"txid": locked_output["txid"], "vout": locked_output["vout"]}], True)
        self.stop_node(0)

        labels_file = self.nodes[0].datadir_path / "bip329_roundtrip.jsonl"
        labels_file_2 = self.nodes[0].datadir_path / "bip329_roundtrip_2.jsonl"
        imported_wallet = "bip329_imported"
        stdout = self.run_wallet_tool(
            "-wallet=bip329_source",
            f"-labelsfile={labels_file}",
            "exportlabels",
        )
        exported_records = self.read_jsonl(labels_file)
        assert_equal(stdout, f"Exported {len(exported_records)} BIP329 records to {labels_file}\n")

        self.log.info("Test rich BIP329 accounting records")
        tx_record = next(
            record for record in exported_records
            if record["type"] == "tx" and record["ref"] == receive_txid
        )
        if "height" in tx_record:
            assert_equal(tx_record["height"], receive_entry["blockheight"])
        assert_equal(tx_record["time"], self.isoformat(receive_entry["time"]))
        assert_equal(tx_record["blockhash"], receive_entry["blockhash"])
        assert_equal(tx_record["value"], self.sats(receive_entry["amount"]))
        assert "fee" not in tx_record
        assert tx_record["origin"].startswith("wpkh([")

        receive_record = next(
            record for record in exported_records
            if record["type"] == "output"
            and record["ref"] == f"{receive_txid}:{receive_entry['vout']}"
            and record.get("category") == "receive"
        )
        assert_equal(receive_record["label"], "receive label")
        assert_equal(receive_record["value"], self.sats(receive_entry["amount"]))
        assert_equal(receive_record["wallet_value"], self.sats(receive_entry["amount"]))
        if "height" in receive_record:
            assert_equal(receive_record["height"], receive_entry["blockheight"])
        assert_equal(receive_record["time"], self.isoformat(receive_entry["time"]))
        assert_equal(receive_record["blockhash"], receive_entry["blockhash"])
        assert_equal(receive_record["address"], receive_address)
        assert receive_record["keypath"].startswith("/0/")
        assert "fee" not in receive_record
        assert_equal(len([record for record in exported_records if record["type"] == "descriptor"]), 8)

        self.assert_tool_output(
            "Topping up keypool...\n" + self.get_expected_info_output(name=imported_wallet, keypool=2000),
            f"-wallet={imported_wallet}",
            "create",
        )
        self.assert_tool_output(
            f"Imported 3 BIP329 records from {labels_file}; ignored {len(exported_records) - 3} unsupported records\n",
            f"-wallet={imported_wallet}",
            f"-labelsfile={labels_file}",
            "importlabels",
        )
        stdout = self.run_wallet_tool(
            f"-wallet={imported_wallet}",
            f"-labelsfile={labels_file_2}",
            "exportlabels",
        )
        imported_export_records = self.read_jsonl(labels_file_2)
        assert_equal(stdout, f"Exported {len(imported_export_records)} BIP329 records to {labels_file_2}\n")
        assert_equal(
            sorted(self.importable_records(exported_records), key=lambda record: (record["type"], record["ref"])),
            sorted(
                self.importable_records(imported_export_records),
                key=lambda record: (record["type"], record["ref"]),
            ),
        )

        self.start_node(0, [f"-wallet={imported_wallet}"])
        imported = self.nodes[0].get_wallet_rpc(imported_wallet)
        assert_equal(imported.getaddressesbylabel("receive label")[receive_address]["purpose"], "send")
        assert_equal(imported.getaddressesbylabel("send label")[external_address]["purpose"], "send")
        assert_equal(
            imported.listlockunspent(),
            [{"txid": locked_output["txid"], "vout": locked_output["vout"]}],
        )
        self.stop_node(0)

    def run_test(self):
        self.test_bip329_vectors()
        self.test_wallet_roundtrip()


if __name__ == "__main__":
    ToolWalletBIP329Test(__file__).main()

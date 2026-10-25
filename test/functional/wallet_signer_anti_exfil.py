#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise Core-managed interactive Taproot anti-exfil signing and failures."""

import json
from pathlib import Path

from wallet_signer import WalletSignerTest
from test_framework.authproxy import JSONRPCException
from test_framework.psbt import PSBT, PSBT_IN_SIGHASH_TYPE, PSBT_IN_TAP_KEY_SIG
from test_framework.script import SIGHASH_ALL
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletSignerAntiExfilTest(WalletSignerTest):
    def set_test_params(self):
        super().set_test_params()

    def run_test(self):
        self.init_mock_node()
        self.test_valid_signer()
        self.restart_node(1, [
            f"-signer={self.mock_signer_path()}",
            "-keypool=10",
            "-signerantiexfil",
        ])
        self.connect_nodes(0, 1)
        self.nodes[1].loadwallet("hww")
        hww = self.nodes[1].get_wallet_rpc("hww")
        inputs = self.create_outpoints(self.nodes[0], outputs=[
            {hww.getnewaddress(address_type="bech32m"): 1} for _ in range(2)
        ])
        self.generate(self.nodes[0], 1, sync_fun=self.sync_except_mock)
        dest = self.nodes[0].getnewaddress()

        self.log.info("Test two-round signing of two inputs with DEFAULT and ALL")
        for psbt_version, hash_type, signature_length in [(0, None, 64), (0, "ALL", 65), (2, None, 64), (2, "ALL", 65)]:
            funded = hww.walletcreatefundedpsbt(
                inputs,
                [{dest: 1.5}],
                options={"add_inputs": False},
                psbt_version=psbt_version,
            )
            if hash_type == "ALL":
                explicit_all = PSBT.from_base64(funded["psbt"])
                for psbt_in in explicit_all.i:
                    psbt_in.map[PSBT_IN_SIGHASH_TYPE] = SIGHASH_ALL.to_bytes(4, "little")
                funded["psbt"] = explicit_all.to_base64()
            kwargs = {} if hash_type is None else {"sighashtype": hash_type}
            # Signing without finalization leaves key signatures for later
            # ScriptPubKeyMans and repeated walletprocesspsbt calls to retain.
            partial = hww.walletprocesspsbt(funded["psbt"], finalize=False, **kwargs)
            assert not partial["complete"]
            for psbt_in in PSBT.from_base64(partial["psbt"]).i:
                assert_equal(len(psbt_in.map[PSBT_IN_TAP_KEY_SIG]), signature_length)
            self.set_mock_sign_mode(self.nodes[1], "ae_unsupported")
            unchanged = hww.walletprocesspsbt(partial["psbt"], finalize=False, **kwargs)
            assert_equal(unchanged["psbt"], partial["psbt"])
            self.clear_mock_sign_mode(self.nodes[1])
            finalized = hww.finalizepsbt(partial["psbt"])
            assert finalized["complete"]
            assert hww.testmempoolaccept([finalized["hex"]])[0]["allowed"]

            result = hww.walletprocesspsbt(funded["psbt"], **kwargs)
            assert result["complete"]
            assert hww.testmempoolaccept([result["hex"]])[0]["allowed"]
            requested = hww.decodepsbt(funded["psbt"])
            returned = hww.decodepsbt(result["psbt"])
            if psbt_version == 0:
                assert_equal(requested["tx"], returned["tx"])
            else:
                for field in ["tx_version", "fallback_locktime"]:
                    assert_equal(requested[field], returned[field])
                assert_equal(len(requested["inputs"]), len(returned["inputs"]))
                assert_equal(len(requested["outputs"]), len(returned["outputs"]))
                for original, signed in zip(requested["inputs"], returned["inputs"]):
                    for field in ["previous_txid", "previous_vout", "sequence"]:
                        assert_equal(original[field], signed[field])
                for original, signed in zip(requested["outputs"], returned["outputs"]):
                    assert_equal(original["amount"], signed["amount"])
                    assert_equal(original["script"]["hex"], signed["script"]["hex"])
            for txin in hww.decoderawtransaction(result["hex"])["vin"]:
                assert_equal(len(bytes.fromhex(txin["txinwitness"][0])), signature_length)
            # Session data must not escape in the completed PSBT.
            for psbt_in in PSBT.from_base64(result["psbt"]).i:
                assert not any(
                    isinstance(key, bytes) and key.startswith(b"\xfc\x02ae")
                    for key in psbt_in.map
                )

        failures = {
            "ae_unsupported": "does not support anti-exfil",
            "ae_missing_nonce": "no valid nonce commitment",
            "ae_early_signature": "before the host reveal",
            "ae_bad_nonce": "nonce proof failed",
            "ae_ignore_entropy": "nonce proof failed",
            "ae_corrupt_signature": "nonce proof failed",
            "ae_abort": "interrupted after nonce commitment",
            "ae_process_failure": "interrupted after nonce commitment",
            "ae_drop_commitment": "changed or omitted the host commitment",
            "ae_change_commitment": "changed or omitted the host commitment",
            "ae_empty_entropy": "returned host entropy before the host reveal",
            "ae_change_sequence": "changed the unsigned transaction",
            "ae_change_utxo": "changed or omitted input UTXO data",
            "ae_extra_script_signature": "returned an unexpected signature",
        }
        for mode, reason in failures.items():
            self.log.info(f"Reject {mode}")
            self.set_mock_sign_mode(self.nodes[1], mode)
            with self.nodes[1].assert_debug_log([reason]):
                assert_raises_rpc_error(
                    -25,
                    "External signer failed to sign",
                    hww.walletprocesspsbt,
                    funded["psbt"],
                )
        self.clear_mock_sign_mode(self.nodes[1])

        self.log.info("Do not expose signer nonce transcripts through RPC errors or debug logs")
        for phase in ("round1", "round2"):
            for channel in ("stdout", "stderr", "error", "psbt"):
                self.set_mock_sign_mode(self.nodes[1], f"ae_log_{phase}_{channel}")
                log_start = self.nodes[1].debug_log_size(encoding="utf-8")
                try:
                    hww.walletprocesspsbt(funded["psbt"])
                except JSONRPCException as error:
                    assert_equal(error.error["code"], -25)
                    rpc_error = error.error["message"]
                else:
                    raise AssertionError("Signer transcript failure was accepted")
                transcript = json.loads((Path(self.nodes[1].cwd) / "mock_anti_exfil_transcript").read_text(encoding="utf8"))
                with self.nodes[1].debug_log_path.open(encoding="utf8") as log:
                    log.seek(log_start)
                    new_log = log.read()
                for value in transcript.values():
                    if value is not None:
                        assert value not in rpc_error
                        assert value not in new_log
                if phase == "round2":
                    assert "interrupted after nonce commitment" in new_log
        self.clear_mock_sign_mode(self.nodes[1])

        self.log.info("Broadcast and confirm after returning to an honest signer")
        result = hww.send(outputs={dest: 1.5}, inputs=inputs, add_inputs=False)
        assert result["complete"]
        assert result["txid"] in self.nodes[1].getrawmempool()
        self.sync_mempools(self.nodes[:2])
        self.generate(self.nodes[0], 1, sync_fun=self.sync_except_mock)
        assert_equal(hww.gettransaction(result["txid"])["confirmations"], 1)


if __name__ == '__main__':
    WalletSignerAntiExfilTest(__file__).main()

# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test-only interactive signer using independent reference arithmetic."""

import base64
import hashlib
import hmac
import json
from pathlib import Path
import sys
from io import BytesIO

from test_framework.address import base58_to_byte
from test_framework.crypto import anti_exfil as ae
from test_framework.key import (
    TaggedHash,
    compute_xonly_pubkey,
    sign_schnorr,
    tweak_add_privkey,
)
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    deser_compact_size,
    from_binary,
)
from test_framework.psbt import (
    PSBT,
    PSBT_GLOBAL_FALLBACK_LOCKTIME,
    PSBT_GLOBAL_TX_VERSION,
    PSBT_GLOBAL_UNSIGNED_TX,
    PSBT_IN_NON_WITNESS_UTXO,
    PSBT_IN_OUTPUT_INDEX,
    PSBT_IN_PREVIOUS_TXID,
    PSBT_IN_SEQUENCE,
    PSBT_IN_SIGHASH_TYPE,
    PSBT_IN_TAP_BIP32_DERIVATION,
    PSBT_IN_TAP_KEY_SIG,
    PSBT_IN_TAP_MERKLE_ROOT,
    PSBT_IN_TAP_SCRIPT_SIG,
    PSBT_IN_WITNESS_UTXO,
    PSBT_OUT_AMOUNT,
    PSBT_OUT_SCRIPT,
)
from test_framework.script import CScript, TaprootSignatureHash

PREFIX = b"\xfc\x02ae"


def signing_key(psbt_input, tprv):
    """Derive the mock wallet's tweaked signing key from its account root."""
    origin = next(
        value for key, value in psbt_input.map.items()
        if isinstance(key, bytes) and key[0] == PSBT_IN_TAP_BIP32_DERIVATION
    )
    stream = BytesIO(origin)
    stream.read(deser_compact_size(stream) * 32)
    stream.read(4)  # The mock fingerprint is metadata, not the root's real fingerprint.
    paths = stream.read()
    # The descriptor's tprv is already its account root. Only derive change/index.
    children = [
        int.from_bytes(paths[offset:offset + 4], "little")
        for offset in range(0, len(paths), 4)
    ][-2:]
    payload, version = base58_to_byte(tprv)
    extended = bytes([version]) + payload
    chain = extended[13:45]
    secret = int.from_bytes(extended[46:78], "big")
    for child in children:
        assert child < 0x80000000
        data = ae.compressed(ae.point_mul(secret)) + child.to_bytes(4, "big")
        derived = hmac.new(chain, data, hashlib.sha512).digest()
        secret = (secret + int.from_bytes(derived[:32], "big")) % ae.N
        chain = derived[32:]
    secret = secret.to_bytes(32, "big")
    pubkey, _ = compute_xonly_pubkey(secret)
    merkle_root = psbt_input.map.get(PSBT_IN_TAP_MERKLE_ROOT, b"")
    return tweak_add_privkey(secret, TaggedHash("TapTweak", pubkey + merkle_root))


def unsigned_transaction(psbt):
    """Reconstruct the wallet-generated transaction used by this mock."""
    if psbt.version == 0:
        return from_binary(CTransaction, psbt.g.map[PSBT_GLOBAL_UNSIGNED_TX])
    tx = CTransaction()
    tx.version = int.from_bytes(psbt.g.map[PSBT_GLOBAL_TX_VERSION], "little", signed=True)
    tx.nLockTime = int.from_bytes(
        psbt.g.map.get(PSBT_GLOBAL_FALLBACK_LOCKTIME, bytes(4)), "little"
    )
    for psbt_input in psbt.i:
        prevout = COutPoint(
            int.from_bytes(psbt_input.map[PSBT_IN_PREVIOUS_TXID], "little"),
            int.from_bytes(psbt_input.map[PSBT_IN_OUTPUT_INDEX], "little"),
        )
        sequence = int.from_bytes(psbt_input.map.get(PSBT_IN_SEQUENCE, b"\xff" * 4), "little")
        tx.vin.append(CTxIn(prevout, nSequence=sequence))
    for psbt_output in psbt.o:
        amount = int.from_bytes(psbt_output.map[PSBT_OUT_AMOUNT], "little", signed=True)
        tx.vout.append(CTxOut(amount, CScript(psbt_output.map[PSBT_OUT_SCRIPT])))
    return tx


def sign_psbt(encoded, mode, tprv):
    psbt = PSBT.from_base64(encoded)
    if mode == "ae_unsupported":
        return {"error": "Device does not support anti-exfil", "code": -9}
    tx = unsigned_transaction(psbt)
    utxos = []
    for index, psbt_input in enumerate(psbt.i):
        if PSBT_IN_WITNESS_UTXO in psbt_input.map:
            utxos.append(from_binary(CTxOut, psbt_input.map[PSBT_IN_WITNESS_UTXO]))
        else:
            prev = from_binary(CTransaction, psbt_input.map[PSBT_IN_NON_WITNESS_UTXO])
            utxos.append(prev.vout[tx.vin[index].prevout.n])

    for index, psbt_input in enumerate(psbt.i):
        commitments = [
            (key[5:], value) for key, value in psbt_input.map.items()
            if isinstance(key, bytes) and key.startswith(PREFIX + b"\x00")
        ]
        for public_key, commitment in commitments:
            hash_type = int.from_bytes(psbt_input.map.get(PSBT_IN_SIGHASH_TYPE, bytes(4)), "little")
            message = TaprootSignatureHash(tx, utxos, hash_type, input_index=index)
            secret = signing_key(psbt_input, tprv)
            assert ae.b32(ae.normalized_key(secret)[1][0]) == public_key
            nonce = ae.signer_commit(secret, message, commitment)
            entropy = psbt_input.map.get(PREFIX + b"\x02" + public_key)
            phase = "round1" if entropy is None else "round2"
            if mode in (f"ae_log_{phase}_stdout", f"ae_log_{phase}_stderr", f"ae_log_{phase}_error", f"ae_log_{phase}_psbt"):
                transcript = {
                    "marker": "ANTI_EXFIL_TRANSCRIPT_MUST_STAY_PRIVATE",
                    "nonce": nonce.hex(),
                    "entropy": entropy.hex() if entropy is not None else None,
                }
                payload = json.dumps(transcript)
                Path("mock_anti_exfil_transcript").write_text(payload, encoding="utf8")
                if mode.endswith("_stdout"):
                    sys.stdout.write("invalid-json:" + payload)
                    raise SystemExit(0)
                if mode.endswith("_stderr"):
                    sys.stderr.write(payload)
                    raise SystemExit(2)
                if mode.endswith("_psbt"):
                    # A duplicate unknown key makes the parser's diagnostic
                    # include attacker-controlled key bytes on ordinary paths.
                    key = b"\x80" + nonce + (entropy or b"")
                    field = bytes([len(key)]) + key + b"\x01\x00"
                    malformed = b"psbt\xff" + field + field + b"\x00"
                    return {"psbt": base64.b64encode(malformed).decode("ascii")}
                return {"error": payload}
            if entropy is None:
                if mode != "ae_missing_nonce":
                    psbt_input.map[PREFIX + b"\x01" + public_key] = nonce
                if mode == "ae_bad_nonce":
                    psbt_input.map[PREFIX + b"\x01" + public_key] = bytes([nonce[0] ^ 1]) + nonce[1:]
                if mode == "ae_early_signature":
                    psbt_input.map[PSBT_IN_TAP_KEY_SIG] = (
                        sign_schnorr(secret, message) + (bytes([hash_type]) if hash_type else b"")
                    )
            else:
                if mode == "ae_abort":
                    return {"error": "Signing interrupted"}
                if mode == "ae_process_failure":
                    raise SystemExit(2)
                signature = ae.signer_sign(secret, message, entropy)
                if mode == "ae_ignore_entropy":
                    signature = sign_schnorr(secret, message)
                elif mode == "ae_corrupt_signature":
                    signature = signature[:-1] + bytes([signature[-1] ^ 1])
                psbt_input.map[PSBT_IN_TAP_KEY_SIG] = (
                    signature + (bytes([hash_type]) if hash_type else b"")
                )

            # These modes deliberately return malformed raw transcripts. Core
            # must reject them before merging can hide conflicts or omitted fields.
            if mode == "ae_drop_commitment":
                del psbt_input.map[PREFIX + b"\x00" + public_key]
            elif mode == "ae_change_commitment":
                psbt_input.map[PREFIX + b"\x00" + public_key] = bytes(32)
            elif mode == "ae_empty_entropy":
                psbt_input.map[PREFIX + b"\x02" + public_key] = b""
            elif mode == "ae_extra_script_signature" and entropy is not None:
                key = bytes([PSBT_IN_TAP_SCRIPT_SIG]) + public_key + bytes(32)
                psbt_input.map[key] = signature[:64]

    if mode == "ae_change_sequence":
        sequence = int.from_bytes(psbt.i[0].map[PSBT_IN_SEQUENCE], "little")
        psbt.i[0].map[PSBT_IN_SEQUENCE] = (sequence ^ 1).to_bytes(4, "little")
    elif mode == "ae_change_utxo":
        value = psbt.i[0].map[PSBT_IN_WITNESS_UTXO]
        amount = int.from_bytes(value[:8], "little")
        psbt.i[0].map[PSBT_IN_WITNESS_UTXO] = (amount - 1).to_bytes(8, "little") + value[8:]
    return {"psbt": psbt.to_base64()}

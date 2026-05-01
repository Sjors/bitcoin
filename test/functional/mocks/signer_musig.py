#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""External signer mock for the BIP388 MuSig2 policy dance.

This mock is driven by files dropped by the test in the node's cwd:

  mock_fingerprint
      Hex-encoded master key fingerprint to advertise from `enumerate`
      and to validate against `--fingerprint`. Required if
      `mock_fingerprints` is not set.

  mock_fingerprints
      Comma-separated list of fingerprints. Used by tests that exercise
      multi-device flows (e.g. a 2-of-2 MuSig2 wallet where two HW
      devices are connected at the same time). The mock then validates
      `--fingerprint` against the set instead of a single value, and
      `enumerate` lists every fingerprint as a separate device.

  mock_signtx_delegate_url
      `signtx` runs the incoming PSBT through `walletprocesspsbt`
      against the bitcoind RPC at this URL (which must already be
      `/wallet/<name>`-suffixed). This lets the mock act as a real
      cosigner in the MuSig2 dance: the cosigner wallet adds its own
      pubnonce and -- once every participant's nonce is in the PSBT --
      its partial signature. Per-fingerprint variants in
      `mock_signtx_delegate_<fingerprint>_url` take precedence so
      multi-device tests can route each fingerprint to its own
      cosigner wallet.

  mock_signtx_<fingerprint>_counter
      Maintained by this script: the number of successful signtx
      invocations seen for this device. Tests assert against it.

  mock_signtx_error
      If present, every policy `signtx` call returns a structured
      `{"error": "<contents>"}` payload (well-formed JSON-error path) and
      does NOT advance the round counter. Used to exercise the soft- and
      hard-fail branches in FillPSBTPolicy without crashing the subprocess.

  mock_displayaddress
      Address to echo from the policy `displayaddress` command. Tests
      stage the expected address (or an intentionally wrong one) here.

  mock_registerpolicy_nohmac
      If present, `register` returns `{}` instead of an `hmac` field.
      Used to exercise signers like Coldcard that key policies by name
      and do not produce a registration hmac.

Only the subset of the signer wire protocol needed for the policy MuSig2
flow is implemented: enumerate, register, signtx (policy variant),
displayaddress (policy variant). It is intentionally separate from
mocks/signer.py so the existing single-sig tests there are unaffected.
"""

import argparse
import base64
import json
import os
import sys
import urllib.parse
import urllib.request


def _state_path(name):
    return os.path.join(os.getcwd(), name)


def _read_state(name):
    path = _state_path(name)
    if not os.path.isfile(path):
        return None
    with open(path, "r") as f:
        return f.read().strip()


def _device_fingerprints():
    fps = _read_state("mock_fingerprints")
    if fps is not None:
        return [fp.strip() for fp in fps.split(",") if fp.strip()]
    fp = _read_state("mock_fingerprint")
    if fp is None:
        sys.stdout.write(json.dumps({"error": "mock_fingerprint not set"}))
        sys.exit(0)
    return [fp]


def _device_fingerprint():
    return _device_fingerprints()[0]


def _validate_fingerprint(args):
    if args.fingerprint not in _device_fingerprints():
        sys.stdout.write(json.dumps({
            "error": "Unexpected fingerprint", "fingerprint": args.fingerprint,
        }))
        return False
    return True


def enumerate_cmd(_args):
    sys.stdout.write(json.dumps([
        {"fingerprint": fp, "type": "mock_musig", "model": "mock_musig"}
        for fp in _device_fingerprints()
    ]))


def getdescriptors_cmd(args):
    # Returned to satisfy createwallet(external_signer=True), which calls
    # SetupDescriptorScriptPubKeyMans during wallet creation. The default
    # account descriptors below are placeholders. To exercise the BIP388
    # policy signing path the test stages MuSig2 descriptor strings via
    # `mock_getdescriptors_bech32m_receive` / `_internal`; when present,
    # those override the BECH32M slots so the wallet imports the policy
    # descriptor as an ExternalSignerScriptPubKeyMan (the only SPKM kind
    # that the BIP388 dispatch in CWallet::FillPSBT recognises).
    xpub = "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B"
    fp = _device_fingerprint()
    tr_recv = _read_state("mock_getdescriptors_bech32m_receive") \
        or f"tr([{fp}/86h/1h/{args.account}']{xpub}/0/*)"
    tr_int = _read_state("mock_getdescriptors_bech32m_internal") \
        or f"tr([{fp}/86h/1h/{args.account}']{xpub}/1/*)"
    sys.stdout.write(json.dumps({
        "receive": [
            f"pkh([{fp}/44h/1h/{args.account}']{xpub}/0/*)",
            f"sh(wpkh([{fp}/49h/1h/{args.account}']{xpub}/0/*))",
            f"wpkh([{fp}/84h/1h/{args.account}']{xpub}/0/*)",
            tr_recv,
        ],
        "internal": [
            f"pkh([{fp}/44h/1h/{args.account}']{xpub}/1/*)",
            f"sh(wpkh([{fp}/49h/1h/{args.account}']{xpub}/1/*))",
            f"wpkh([{fp}/84h/1h/{args.account}']{xpub}/1/*)",
            tr_int,
        ],
    }))


def register_cmd(args):
    if not _validate_fingerprint(args):
        return
    if _read_state("mock_registerpolicy_nohmac") is not None:
        return sys.stdout.write(json.dumps({}))
    # Deterministic dummy hmac; the wallet only needs IsHex(hmac) to pass.
    sys.stdout.write(json.dumps({
        "hmac": "00" * 32,
    }))


def signtx_cmd(args):
    if not _validate_fingerprint(args):
        return
    # Test-injected subprocess-crash path. The wallet's policy signing
    # call invokes RunCommandParseJSON, which throws std::runtime_error
    # if the subprocess exits non-zero. Used to exercise the try/catch
    # in FillPSBTPolicy.
    if _read_state("mock_signtx_crash") is not None:
        sys.stderr.write("mock signer crashed\n")
        sys.exit(1)

    # Test-injected error path. Counter is intentionally NOT advanced so
    # repeat calls keep failing the same way (mirrors a device that's
    # unplugged for the duration of the test scenario).
    err = _read_state("mock_signtx_error")
    if err is not None:
        return sys.stdout.write(json.dumps({"error": err}))

    if args.policy_name is None:
        return sys.stdout.write(json.dumps({
            "error": "signer_musig.py only implements the policy signtx path",
        }))
    if _read_state("mock_registerpolicy_nohmac") is not None and args.hmac is not None:
        return sys.stdout.write(json.dumps({
            "error": f"Unexpected hmac: {args.hmac}",
        }))

    fp = args.fingerprint
    counter_path = _state_path(f"mock_signtx_{fp}_counter")
    counter = 1
    if os.path.isfile(counter_path):
        with open(counter_path, "r") as f:
            counter = int(f.read().strip()) + 1

    delegate_url = _read_state(f"mock_signtx_delegate_{fp}_url") \
        or _read_state("mock_signtx_delegate_url")
    if delegate_url is not None:
        # urllib does not turn URL-embedded credentials into a Basic
        # Authorization header on its own; do it manually.
        parsed = urllib.parse.urlparse(delegate_url)
        netloc = parsed.hostname or ""
        if parsed.port is not None:
            netloc += f":{parsed.port}"
        rebuilt = urllib.parse.urlunparse(parsed._replace(netloc=netloc))
        body = json.dumps({
            "jsonrpc": "1.0",
            "id": "signer_musig",
            "method": "walletprocesspsbt",
            "params": [args.psbt],
        }).encode()
        headers = {"Content-Type": "application/json", "Content-Length": str(len(body))}
        if parsed.username is not None:
            userpass = f"{parsed.username}:{parsed.password or ''}".encode()
            headers["Authorization"] = "Basic " + base64.b64encode(userpass).decode()
        req = urllib.request.Request(rebuilt, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            reply = json.loads(resp.read())
        if reply.get("error"):
            return sys.stdout.write(json.dumps({"error": str(reply["error"])}))
        with open(counter_path, "w") as f:
            f.write(str(counter))
        return sys.stdout.write(json.dumps({"psbt": reply["result"]["psbt"]}))

    sys.stdout.write(json.dumps({"error": "no mock_signtx_delegate_url configured"}))


def displayaddress_cmd(args):
    if not _validate_fingerprint(args):
        return
    if _read_state("mock_registerpolicy_nohmac") is not None and args.hmac is not None:
        return sys.stdout.write(json.dumps({
            "error": f"Unexpected hmac: {args.hmac}",
        }))
    addr = _read_state("mock_displayaddress")
    if addr is None:
        return sys.stdout.write(json.dumps({
            "error": "mock_displayaddress not set",
        }))
    sys.stdout.write(json.dumps({"address": addr}))


parser = argparse.ArgumentParser(prog='./signer_musig.py', description='External MuSig2 signer mock')
parser.add_argument('--fingerprint')
parser.add_argument('--chain', default='main')
parser.add_argument('--stdin', action='store_true')

subparsers = parser.add_subparsers(description='Commands', dest='command')
subparsers.required = True

parser_enumerate = subparsers.add_parser('enumerate')
parser_enumerate.set_defaults(func=enumerate_cmd)

parser_getdescriptors = subparsers.add_parser('getdescriptors')
parser_getdescriptors.add_argument('--account')
parser_getdescriptors.set_defaults(func=getdescriptors_cmd)

parser_register = subparsers.add_parser('register')
parser_register.add_argument('--name')
parser_register.add_argument('--desc')
parser_register.add_argument('--key', action='append')
parser_register.set_defaults(func=register_cmd)

parser_signtx = subparsers.add_parser('signtx')
parser_signtx.add_argument('psbt', metavar='psbt')
parser_signtx.add_argument('--policy-name', dest='policy_name', default=None)
parser_signtx.add_argument('--policy-desc', dest='policy_desc', default=None)
parser_signtx.add_argument('--hmac', default=None)
parser_signtx.add_argument('--key', action='append', default=[])
parser_signtx.set_defaults(func=signtx_cmd)

parser_displayaddress = subparsers.add_parser('displayaddress')
parser_displayaddress.add_argument('--desc', default=None)
parser_displayaddress.add_argument('--policy-name', dest='policy_name', default=None)
parser_displayaddress.add_argument('--policy-desc', dest='policy_desc', default=None)
parser_displayaddress.add_argument('--hmac', default=None)
parser_displayaddress.add_argument('--key', action='append', default=[])
parser_displayaddress.add_argument('--index', type=int, default=None)
parser_displayaddress.add_argument('--change', action='store_true')
parser_displayaddress.set_defaults(func=displayaddress_cmd)

if not sys.stdin.isatty():
    buffer = sys.stdin.read()
    if buffer and buffer.rstrip() != "":
        sys.argv.extend(buffer.rstrip().split(" "))

args = parser.parse_args()
args.func(args)

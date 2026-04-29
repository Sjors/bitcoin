#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""External signer mock for the MuSig2 registered-descriptor display flow.

This mock is driven by files dropped by the test in the node's cwd:

  mock_fingerprint
      Hex-encoded master key fingerprint to advertise from `enumerate`
      and to validate against `--fingerprint`. Required.

  mock_displayaddress
      Address to echo from the registered `displayaddress` command. Tests
      stage the expected address (or an intentionally wrong one) here.

Only the subset of the signer wire protocol needed for this flow is
implemented: enumerate, registerdescriptor, and registered displayaddress.
It is intentionally separate from mocks/signer.py so the
existing single-sig tests there are unaffected.
"""

import argparse
import base64
import json
import os
import sys


def _state_path(name):
    return os.path.join(os.getcwd(), name)


def _read_state(name):
    path = _state_path(name)
    if not os.path.isfile(path):
        return None
    with open(path, "r") as f:
        return f.read().strip()


def _device_fingerprint():
    fp = _read_state("mock_fingerprint")
    if fp is None:
        sys.stdout.write(json.dumps({"error": "mock_fingerprint not set"}))
        sys.exit(0)
    return fp


def _validate_fingerprint(args):
    if args.fingerprint != _device_fingerprint():
        sys.stdout.write(json.dumps({
            "error": "Unexpected fingerprint", "fingerprint": args.fingerprint,
        }))
        return False
    return True


def enumerate_cmd(_args):
    sys.stdout.write(json.dumps([
        {"fingerprint": _device_fingerprint(), "type": "mock_musig", "model": "mock_musig"}
    ]))


def getdescriptors_cmd(args):
    # Returned to satisfy createwallet(external_signer=True), which calls
    # SetupDescriptorScriptPubKeyMans during wallet creation. The default
    # account descriptors below are placeholders. To exercise registered
    # descriptor display the test stages MuSig2 descriptor strings
    # via `mock_getdescriptors_bech32m_receive` / `_internal`; when present,
    # those override the BECH32M slots so the wallet imports the registered
    # descriptor as an ExternalSignerScriptPubKeyMan (the only SPKM kind
    # that the registration dispatch in CWallet recognises).
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


def registerdescriptor_cmd(args):
    if not _validate_fingerprint(args):
        return
    payload = json.dumps({
        "fingerprint": args.fingerprint,
        "name": args.name,
        "descriptor": args.descriptor,
    }).encode()
    sys.stdout.write(json.dumps({
        "registration": base64.b64encode(payload).decode(),
    }))


def _validate_registration(args):
    if args.registration is None:
        sys.stdout.write(json.dumps({"error": "Missing registration"}))
        return False
    try:
        payload = json.loads(base64.b64decode(args.registration))
    except Exception:
        sys.stdout.write(json.dumps({"error": "Invalid registration"}))
        return False
    if payload.get("fingerprint") != args.fingerprint:
        sys.stdout.write(json.dumps({"error": "Registration fingerprint mismatch"}))
        return False
    return True


def displayaddress_cmd(args):
    if not _validate_fingerprint(args) or not _validate_registration(args):
        return
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

parser_register = subparsers.add_parser('registerdescriptor')
parser_register.add_argument('name')
parser_register.add_argument('descriptor')
parser_register.set_defaults(func=registerdescriptor_cmd)

parser_displayaddress = subparsers.add_parser('displayaddress')
parser_displayaddress.add_argument('--desc', default=None)
parser_displayaddress.add_argument('--registration', default=None)
parser_displayaddress.add_argument('--index', type=int, default=None)
parser_displayaddress.add_argument('--change', action='store_true')
parser_displayaddress.set_defaults(func=displayaddress_cmd)

if not sys.stdin.isatty():
    buffer = sys.stdin.read()
    if buffer and buffer.rstrip() != "":
        sys.argv.extend(buffer.rstrip().split(" "))

args = parser.parse_args()
args.func(args)

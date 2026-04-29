#!/usr/bin/env python3
# Copyright (c) 2018-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import os
import sys
import argparse
import base64
import json
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from test_framework.authproxy import AuthServiceProxy, JSONRPCException
from test_framework.psbt import (
    PSBT,
    PSBT_IN_PARTIAL_SIG,
    PSBT_IN_SIGHASH_TYPE,
    PSBT_IN_TAP_KEY_SIG,
    PSBT_OUT_AMOUNT,
    PSBT_OUT_SCRIPT,
)

# Master private key for the tpub in getdescriptors below. Used by signtx,
# which imports the keys into a wallet on the offline node provided by the
# test and lets it do the actual signing.
tprv = "tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK"

MOCK_WALLET = "mock"
DEFAULT_FINGERPRINT = "00000001"
DEFAULT_REGISTRATION = "cmRlc2MBBHRlc3Q="


def read_state(name):
    path = os.path.join(os.getcwd(), name)
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf8") as f:
        return f.read().strip()


def device_fingerprint():
    return read_state("mock_fingerprint") or DEFAULT_FINGERPRINT


def validate_fingerprint(args):
    if args.fingerprint != device_fingerprint():
        sys.stdout.write(json.dumps({"error": "Unexpected fingerprint", "fingerprint": args.fingerprint}))
        return False
    return True


def perform_pre_checks():
    mock_result_path = os.path.join(os.getcwd(), "mock_result")
    if os.path.isfile(mock_result_path):
        with open(mock_result_path, "r") as f:
            mock_result = f.read()
        if mock_result[0]:
            sys.stdout.write(mock_result[2:])
            sys.exit(int(mock_result[0]))

def enumerate(args):
    sys.stdout.write(json.dumps([{"fingerprint": device_fingerprint(), "type": "trezor", "model": "trezor_t"}]))

def getdescriptors(args):
    xpub = "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B"

    sys.stdout.write(json.dumps({
        "receive": [
            "pkh([00000001/44h/1h/" + args.account + "']" + xpub + "/0/*)#aqllu46s",
            "sh(wpkh([00000001/49h/1h/" + args.account + "']" + xpub + "/0/*))#5dh56mgg",
            "wpkh([00000001/84h/1h/" + args.account + "']" + xpub + "/0/*)#h62dxaej",
            "tr([00000001/86h/1h/" + args.account + "']" + xpub + "/0/*)#pcd5w87f"
        ],
        "internal": [
            "pkh([00000001/44h/1h/" + args.account + "']" + xpub + "/1/*)#v567pq2g",
            "sh(wpkh([00000001/49h/1h/" + args.account + "']" + xpub + "/1/*))#pvezzyah",
            "wpkh([00000001/84h/1h/" + args.account + "']" + xpub + "/1/*)#xw0vmgf2",
            "tr([00000001/86h/1h/" + args.account + "']" + xpub + "/1/*)#svg4njw3"

        ]
    }))


def displayaddress(args):
    if not validate_fingerprint(args):
        return

    if args.registration is not None and not validate_registration(args):
        return

    address = read_state("mock_displayaddress")
    if address is not None:
        return sys.stdout.write(json.dumps({"address": address}))
    if args.registration is not None:
        return sys.stdout.write(json.dumps({"error": "mock_displayaddress not set"}))

    if args.fingerprint != DEFAULT_FINGERPRINT:
        return sys.stdout.write(json.dumps({"error": "Unexpected descriptor signer"}))

    expected_desc = {
        "wpkh([00000001/84h/1h/0h/0/0]02c97dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7)#3te6hhy7": "bcrt1qm90ugl4d48jv8n6e5t9ln6t9zlpm5th68x4f8g",
        "sh(wpkh([00000001/49h/1h/0h/0/0]02c97dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7))#kz9y5w82": "2N2gQKzjUe47gM8p1JZxaAkTcoHPXV6YyVp",
        "pkh([00000001/44h/1h/0h/0/0]02c97dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7)#q3pqd8wh": "n1LKejAadN6hg2FrBXoU1KrwX4uK16mco9",
        "tr([00000001/86h/1h/0h/0/0]c97dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7)#puqqa90m": "tb1phw4cgpt6cd30kz9k4wkpwm872cdvhss29jga2xpmftelhqll62mscq0k4g",
        "wpkh([00000001/84h/1h/0h/0/1]03a20a46308be0b8ded6dff0a22b10b4245c587ccf23f3b4a303885be3a524f172)#aqpjv5xr": "wrong_address",
    }
    if args.desc not in expected_desc:
        return sys.stdout.write(json.dumps({"error": "Unexpected descriptor", "desc": args.desc}))

    return sys.stdout.write(json.dumps({"address": expected_desc[args.desc]}))

def get_mock_wallet():
    """RPC connection to the wallet holding our private keys, created on
    first use. The test provides a dedicated offline node for it and passes
    the node's RPC URL via a file in our working directory."""
    with open(os.path.join(os.getcwd(), "mock_rpc_url"), "r", encoding="utf8") as f:
        node_url = f.read().strip()
    node = AuthServiceProxy(node_url)
    wallet = AuthServiceProxy(f"{node_url}/wallet/{MOCK_WALLET}")
    try:
        node.loadwallet(filename=MOCK_WALLET)
        return wallet
    except JSONRPCException as e:
        if e.error["code"] == -35:  # RPC_WALLET_ALREADY_LOADED
            return wallet
        if e.error["code"] != -18:  # RPC_WALLET_NOT_FOUND
            raise
    node.createwallet(wallet_name=MOCK_WALLET, blank=True)
    requests = []
    for desc in [f"pkh({tprv}/<0;1>/*)", f"sh(wpkh({tprv}/<0;1>/*))", f"wpkh({tprv}/<0;1>/*)", f"tr({tprv}/<0;1>/*)"]:
        checksum = node.getdescriptorinfo(descriptor=desc)["checksum"]
        requests.append({"desc": f"{desc}#{checksum}", "timestamp": "now", "range": [0, 99]})
    result = wallet.importdescriptors(requests=requests)
    assert all(r["success"] for r in result)
    return wallet

def tamper(psbt_b64, mode):
    """Alter the transaction described by the (version 2) PSBT before signing
    it, like a rogue or broken signer might."""
    psbt = PSBT.from_base64(psbt_b64)
    if mode == "change_amount":
        # Steal from the output by redirecting the value to fees
        amount = int.from_bytes(psbt.o[0].map[PSBT_OUT_AMOUNT], "little", signed=True)
        psbt.o[0].map[PSBT_OUT_AMOUNT] = (amount - 1).to_bytes(8, "little", signed=True)
    elif mode == "change_script":
        psbt.o[0].map[PSBT_OUT_SCRIPT] = bytes([0x51])  # OP_TRUE
    elif mode == "remove_output":
        psbt.o.pop()
    return psbt.to_base64()

def registerdescriptor(args):
    if not validate_fingerprint(args):
        return

    if "/<0;1>/*" not in args.descriptor:
        return sys.stdout.write(json.dumps({"error": "Expected multipath descriptor", "descriptor": args.descriptor}))
    if args.fingerprint == DEFAULT_FINGERPRINT and read_state("mock_fingerprint") is None:
        registration = DEFAULT_REGISTRATION
    else:
        registration = base64.b64encode(json.dumps({
            "descriptor": args.descriptor,
            "fingerprint": args.fingerprint,
            "name": args.name,
        }, sort_keys=True).encode()).decode()
    return sys.stdout.write(json.dumps({"registration": registration}))


def validate_registration(args):
    if args.fingerprint == DEFAULT_FINGERPRINT and args.registration == DEFAULT_REGISTRATION:
        return True
    try:
        registration = json.loads(base64.b64decode(args.registration))
    except Exception:
        sys.stdout.write(json.dumps({"error": "Invalid registration"}))
        return False
    if registration.get("fingerprint") != args.fingerprint:
        sys.stdout.write(json.dumps({"error": "Registration fingerprint mismatch"}))
        return False
    return True

def registered_signtx(args):
    error = read_state("mock_signtx_error")
    if error is not None:
        return sys.stdout.write(json.dumps({"error": error}))
    if not validate_registration(args):
        return

    delegate_url = read_state("mock_signtx_delegate_url")
    if delegate_url is None:
        return sys.stdout.write(json.dumps({"error": "no mock_signtx_delegate_url configured"}))

    parsed = urllib.parse.urlparse(delegate_url)
    netloc = parsed.hostname or ""
    if parsed.port is not None:
        netloc += f":{parsed.port}"
    rebuilt = urllib.parse.urlunparse(parsed._replace(netloc=netloc))
    body = json.dumps({
        "jsonrpc": "1.0",
        "id": "signer",
        "method": "walletprocesspsbt",
        "params": [args.psbt],
    }).encode()
    headers = {"Content-Type": "application/json", "Content-Length": str(len(body))}
    if parsed.username is not None:
        userpass = f"{parsed.username}:{parsed.password or ''}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(userpass).decode()
    request = urllib.request.Request(rebuilt, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=30) as response:
        reply = json.loads(response.read())
    if reply.get("error"):
        return sys.stdout.write(json.dumps({"error": str(reply["error"])}))

    counter_path = os.path.join(os.getcwd(), "mock_signtx_counter")
    counter = 1
    if os.path.isfile(counter_path):
        with open(counter_path, "r", encoding="utf8") as f:
            counter = int(f.read().strip()) + 1
    with open(counter_path, "w", encoding="utf8") as f:
        f.write(str(counter))
    return sys.stdout.write(json.dumps({"psbt": reply["result"]["psbt"]}))


def signtx(args):
    if not validate_fingerprint(args):
        return
    if args.registration is not None:
        return registered_signtx(args)

    # The test can instruct us to sign in a specific, possibly misbehaving, way
    mode = None
    sign_mode_path = os.path.join(os.getcwd(), "mock_sign_mode")
    if os.path.isfile(sign_mode_path):
        with open(sign_mode_path, "r", encoding="utf8") as f:
            mode = f.read().strip()

    psbt = args.psbt
    if mode in ("change_amount", "change_script", "remove_output"):
        psbt = tamper(psbt, mode)

    sign_options = {}
    if mode in ("sighash_none", "sighash_none_hidden"):
        sign_options["sighashtype"] = "NONE"
    elif mode == "sighash_all_anyonecanpay":
        sign_options["sighashtype"] = "ALL|ANYONECANPAY"

    result = get_mock_wallet().walletprocesspsbt(psbt=psbt, sign=True, bip32derivs=False, finalize=False, **sign_options)
    reply = result["psbt"]

    if mode == "sighash_none_hidden":
        # Drop the declared sighash type, leaving only the signatures
        # themselves to reveal it
        signed = PSBT.from_base64(reply)
        for psbt_in in signed.i:
            psbt_in.map.pop(PSBT_IN_SIGHASH_TYPE, None)
        reply = signed.to_base64()
    elif mode == "strip":
        # Return only the signatures, plus the fields required to describe
        # the same transaction
        signed = PSBT.from_base64(reply)
        stripped = PSBT.from_base64(reply)
        stripped.make_blank()
        for signed_in, stripped_in in zip(signed.i, stripped.i):
            for key, value in signed_in.map.items():
                if key == PSBT_IN_TAP_KEY_SIG or (isinstance(key, bytes) and key[0] == PSBT_IN_PARTIAL_SIG):
                    stripped_in.map[key] = value
        reply = stripped.to_base64()

    sys.stdout.write(json.dumps({"psbt": reply}))

parser = argparse.ArgumentParser(prog='./signer.py', description='External signer mock')
parser.add_argument('--fingerprint')
parser.add_argument('--chain', default='main')
parser.add_argument('--stdin', action='store_true')

subparsers = parser.add_subparsers(description='Commands', dest='command')
subparsers.required = True

parser_enumerate = subparsers.add_parser('enumerate', help='list available signers')
parser_enumerate.set_defaults(func=enumerate)

parser_getdescriptors = subparsers.add_parser('getdescriptors')
parser_getdescriptors.set_defaults(func=getdescriptors)
parser_getdescriptors.add_argument('--account', metavar='account')

parser_displayaddress = subparsers.add_parser('displayaddress', help='display address on signer')
parser_displayaddress.add_argument('--desc', metavar='desc', default=None)
parser_displayaddress.add_argument('--registration', default=None)
parser_displayaddress.add_argument('--index', type=int, default=None)
parser_displayaddress.add_argument('--multipath-index', type=int, default=0)
parser_displayaddress.set_defaults(func=displayaddress)

parser_register = subparsers.add_parser('registerdescriptor')
parser_register.add_argument('name')
parser_register.add_argument('descriptor')
parser_register.set_defaults(func=registerdescriptor)

parser_signtx = subparsers.add_parser('signtx')
parser_signtx.add_argument('psbt', metavar='psbt')
parser_signtx.add_argument('--registration', default=None)

parser_signtx.set_defaults(func=signtx)

if not sys.stdin.isatty():
    buffer = sys.stdin.read()
    if buffer and buffer.rstrip() != "":
        sys.argv.extend(buffer.rstrip().split(" "))

args = parser.parse_args()

perform_pre_checks()

args.func(args)

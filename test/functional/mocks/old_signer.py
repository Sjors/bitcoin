#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Mock of an external signer that predates the getdescriptors --multipath
# argument. Passing that argument makes it exit with an error, rather than
# silently returning single path descriptors.

import sys
import argparse
import json

def enumerate(args):
    sys.stdout.write(json.dumps([{"fingerprint": "00000001", "type": "trezor", "model": "trezor_t"}]))

def getdescriptors(args):
    xpub = "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B"

    sys.stdout.write(json.dumps({
        "receive": [
            "wpkh([00000001/84h/1h/" + args.account + "']" + xpub + "/0/*)#h62dxaej"
        ],
        "internal": [
            "wpkh([00000001/84h/1h/" + args.account + "']" + xpub + "/1/*)#xw0vmgf2"
        ]
    }))

parser = argparse.ArgumentParser(prog='./old_signer.py', description='External signer mock without multipath support')
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

args = parser.parse_args()

args.func(args)

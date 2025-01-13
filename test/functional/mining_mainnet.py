#!/usr/bin/env python3
# Copyright (c) 2025 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test mining on an alternate mainnet

Test mining related RPCs that involve difficulty adjustment, which
regtest doesn't have. It uses an alternate mainnet chain.

For easier testing the difficulty is maximally increased in the first (and only)
regarget period, by producing blocks approximately 2 minutes apart.

The alternate mainnet chain was generated as follows:
- use faketime to set node clock to 2 minutes after genesis block
- mine a block using a CPU miner such as https://github.com/pooler/cpuminer
- restart node with a faketime 2 minutes later

for i in {1..2015}
do
 faketime "`date -d @"$(( 1231006505 + $i * 120 ))"  +'%Y-%m-%d %H:%M:%S'`" \
 bitcoind -connect=0 -nocheckpoints -stopatheight=$i
done

The CPU miner is kept running as follows:

./minerd --coinbase-addr ... --no-stratum --algo sha256d --no-longpoll --scantime 3 --retry-pause 1

This makes each block determinisic except for its timestamp and nonce, which
are stored in data/mainnet_alt.json and used to reconstruct the chain without
having to redo the proof-of-work.

The timestamp was not kept constant because at difficulty 1 it's not sufficient
to only grind the nonce. Grinding the extra_nonce or version field instead
would have required additional (stratum) software. It would also make it more
complicated to reconstruct the blocks in this test.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)
from test_framework.blocktools import (
    DIFF_1_N_BITS,
    DIFF_1_TARGET,
    DIFF_4_N_BITS,
    DIFF_4_TARGET,
    create_coinbase,
    nbits_str,
    target_str
)

from test_framework.messages import (
    CBlock,
    tx_from_hex,
)

import json
import os

# Derived from first BIP32 test vector master key:
# Use pkh() because tr() outputs at low heights are not spendable (unexpected-witness)
COINBASE_OUTPUT_DESCRIPTOR="pkh(xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/44h/0h/0h/<0;1>/*)#fkjtr0yn"

class MiningMainnetTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.chain = "" # main

    def add_options(self, parser):
        parser.add_argument(
            '--datafile',
            default='data/mainnet_alt.json',
            help='Block data file (default: %(default)s)',
        )

        self.add_wallet_options(parser)

    def run_test(self):
        node = self.nodes[0]
        # Clear disk space warning
        node.stderr.seek(0)
        node.stderr.truncate()
        self.log.info("Load alternative mainnet blocks")
        path = os.path.join(os.path.dirname(os.path.realpath(__file__)), self.options.datafile)
        prev_hash = node.getbestblockhash()
        # 1NQpH6Nf8QtR2HphLRcvuVqfhXBXsiWn8r (see descriptor above)
        coinbase_script = bytes.fromhex("76a914eadbac7f36c37e39361168b7aaee3cb24a25312d88ac")
        with open(path, encoding='utf-8') as f:
            blocks = json.load(f)
            n_blocks = len(blocks['timestamps'])
            assert_equal(n_blocks, 2015)
            for i in range(n_blocks):
                self.log.debug(f"height={i+1}")
                block = CBlock()
                block.nVersion = 0x20000000
                block.hashPrevBlock = int(prev_hash, 16)
                block.nTime = blocks['timestamps'][i]
                block.nBits = DIFF_1_N_BITS
                block.nNonce = blocks['nonces'][i]
                block.vtx = [create_coinbase(height=i + 1, script_pubkey=coinbase_script, retarget_period=2016)]
                block.hashMerkleRoot = block.calc_merkle_root()
                block.rehash()
                block_hex = block.serialize(with_witness=True).hex()
                self.log.debug(block_hex)
                assert_equal(node.submitblock(block_hex), None)
                prev_hash = node.getbestblockhash()
                assert_equal(prev_hash, block.hash)

        assert_equal(node.getblockcount(), 2015)

        mining_info = node.getmininginfo()
        assert_equal(mining_info['difficulty'], 1)
        assert_equal(mining_info['bits'], nbits_str(DIFF_1_N_BITS))
        assert_equal(mining_info['target'], target_str(DIFF_1_TARGET))

        assert_equal(mining_info['next']['height'], 2016)
        assert_equal(mining_info['next']['difficulty'], 4)
        assert_equal(mining_info['next']['bits'], nbits_str(DIFF_4_N_BITS))
        assert_equal(mining_info['next']['target'], target_str(DIFF_4_TARGET))

        assert_equal(node.getdifficulty(next=True), 4)
        assert_equal(node.gettarget(next=True), target_str(DIFF_4_TARGET))

        # Check that generated coins are spendable
        if self.is_wallet_compiled():
            node.createwallet(wallet_name="wallet", blank=True)
            wallet = node.get_wallet_rpc("wallet")
            res = wallet.importdescriptors([{
                "desc": COINBASE_OUTPUT_DESCRIPTOR,
                "timestamp": 0,
                "active": True
            }])
            assert(res[0]['success'])
            address = "1NQpH6Nf8QtR2HphLRcvuVqfhXBXsiWn8r"
            info = wallet.getaddressinfo(address)
            print(info)
            assert(info['ismine'])
            address_2 = wallet.getnewaddress(address_type="legacy")
            res = wallet.send(outputs={address_2: 1}, inputs=[{"txid": "bb33a069b1892a63a863cb56bbf2ad839581e961d69038a77b5cfeee4ee48416", "vout": 0}], change_position=1)
            assert(res['complete'])
            assert_equal(node.getrawmempool(), [res['txid']])
            tx_hex = node.getrawtransaction(res['txid'], 0)
            assert_equal(res['txid'], "dda7ed7c2912b3db1d5a67fc728a4dfeedeb5b8fce6578ace9a80f0817051cb7")

            # Mine transaction
            block = CBlock()
            block.nVersion = 0x20000000
            block.hashPrevBlock = int(prev_hash, 16)
            # block.nTime = blocks['timestamps'][2016]
            block.nBits = DIFF_1_N_BITS
            # block.nNonce = blocks['nonces'][2016]
            block.vtx = [
                create_coinbase(height=i + 1, script_pubkey=coinbase_script, retarget_period=2016),
                tx_from_hex(tx_hex)
            ]
            block.hashMerkleRoot = block.calc_merkle_root()
            block.rehash()
            block_hex = block.serialize(with_witness=True).hex()
            self.log.debug(block_hex)
            assert_equal(node.submitblock(block_hex), None)
            prev_hash = node.getbestblockhash()
            assert_equal(prev_hash, block.hash)


if __name__ == '__main__':
    MiningMainnetTest(__file__).main()

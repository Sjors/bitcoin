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
- coinbase address derived from first BIP32 test vector master key:
  tr(xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/86h/0h/0h/0/0)#d6vpenmd
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
)

import json
import os

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

    def run_test(self):
        node = self.nodes[0]
        # Clear disk space warning
        node.stderr.seek(0)
        node.stderr.truncate()
        self.log.info("Load alternative mainnet blocks")
        path = os.path.join(os.path.dirname(os.path.realpath(__file__)), self.options.datafile)
        prev_hash = node.getbestblockhash()
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
                # bc1pqqeyhah6g75dwr942xv40h255q4nshqw4k8ylyhe7plej2eg3mnqz9w4np (see descriptor above)
                block.vtx = [create_coinbase(height=i + 1, script_pubkey=bytes.fromhex("512000324bf6fa47a8d70cb5519957dd54a02b385c0ead8e4f92f9f07f992b288ee6"), retarget_period=2016)]
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

if __name__ == '__main__':
    MiningMainnetTest(__file__).main()

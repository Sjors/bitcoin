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
COINBASE_SCRIPT_PUBKEY="76a914eadbac7f36c37e39361168b7aaee3cb24a25312d88ac"

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

    def mine(self, height, prev_hash, blocks, node, txs=None, fees=0):
        self.log.debug(f"height={height}")
        block = CBlock()
        block.nVersion = 0x20000000
        block.hashPrevBlock = int(prev_hash, 16)
        block.nTime = blocks['timestamps'][height - 1]
        block.nBits = DIFF_1_N_BITS
        block.nNonce = blocks['nonces'][height - 1]
        block.vtx = [] if txs is None else txs
        # 1NQpH6Nf8QtR2HphLRcvuVqfhXBXsiWn8r (see descriptor above)
        coinbase_script = bytes.fromhex(COINBASE_SCRIPT_PUBKEY)
        block.vtx.insert(0, create_coinbase(height=height, script_pubkey=coinbase_script, retarget_period=2016, fees=fees))
        block.hashMerkleRoot = block.calc_merkle_root()
        block.rehash()
        block_hex = block.serialize(with_witness=False).hex()
        self.log.debug(block_hex)
        assert_equal(node.submitblock(block_hex), None)
        prev_hash = node.getbestblockhash()
        assert_equal(prev_hash, block.hash)
        return prev_hash


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
            for i in range(2014):
                prev_hash = self.mine(i + 1, prev_hash, blocks, node)

        assert_equal(node.getblockcount(), 2014)

        # For the last block of the retarget period, check that previously generated
        # coins are spendable.
        tx_hex = "02000000010bf26bc93a554005ea8df44e8c7ab40ef2e2b94a44d3d1a2fd9b25606e7ba313000000006a47304402205258439112356e26f3cd1d71ac8da7c2f31421c2f98d98b8b643beeb03ddc8b9022009b9a1c0d1bface153ad10caf8860d5bd8c27fb46759720edcd21d78f91d7a8d01210239b4b3a27cd1dd8993038d5eb6449220b350c32ae62fec0833b93db8a49031c5fdffffff0200e1f505000000001976a9144002d20168718acbc3b05de8504b138c7a13436d88ac6cff0f24010000001976a914922c2841f27c4778f97ba6c71e0a79685a6f2c4088ac00000000"

        if self.is_wallet_compiled():
            self.log.info("Verify hardcoded coinbase spending transaction by generating it")
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
            assert(info['ismine'])
            assert_equal(info['scriptPubKey'], COINBASE_SCRIPT_PUBKEY)
            address_2 = wallet.getnewaddress(address_type="legacy")
            res = wallet.send(
                outputs={address_2: 1},
                inputs=[{"txid": "13a37b6e60259bfda2d1d3444ab9e2f20eb47a8c4ef48dea0540553ac96bf20b", "vout": 0}],
                change_position=1,
                add_to_wallet=False
            )
            assert(res['complete'])
            assert_equal(res['hex'], tx_hex)

        self.log.info("Spend early coinbase transaction")
        # Mine block with this transaction
        prev_hash = self.mine(2015, prev_hash, blocks, node, [tx_from_hex(tx_hex)], 4500)

        self.log.info("Check difficulty adjustment with getmininginfo")
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

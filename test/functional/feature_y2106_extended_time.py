#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the draft post-2106 extended block timestamp hard fork."""

from io import BytesIO

from test_framework.blocktools import (
    NORMAL_GBT_REQUEST_PARAMS,
    create_block,
)
from test_framework.messages import CBlockHeader, uint256_from_compact
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet


TIME_2106 = 2**32 - 1
MAX_UINT64 = 2**64 - 1


class Y2106ExtendedTimeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def skip_test_if_missing_module(self):
        self.skip_if_no_previous_releases()

    def setup_network(self):
        self.add_nodes(
            self.num_nodes,
            versions=[
                None,
                310000,
            ],
        )

    def submit_to_previous_release(self, block_hex):
        assert_equal(self.nodes[1].submitblock(block_hex), "high-hash")

    def solve_with_zero_low_nonce_byte(self, block):
        target = uint256_from_compact(block.nBits)
        block.nNonce = 0
        while block.hash_int > target:
            block.nNonce += 256

    def run_test(self):
        self.start_nodes()
        wallet = MiniWallet(self.nodes[0])

        self.log.info("Reject extended timestamp encoding below 2**32")
        tmpl = self.nodes[0].getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        bad_low_time_block = create_block(tmpl=tmpl)
        bad_low_time_block.nTime = 0
        bad_low_time_block.set_extended_time_encoding()
        bad_low_time_block.solve()
        assert_equal(self.nodes[0].submitblock(bad_low_time_block.serialize().hex()), "bad-time-encoding")

        self.log.info("Allow the maximum uint64 timestamp past header validation")
        max_time_block = create_block(tmpl=tmpl)
        max_time_block.nTime = MAX_UINT64
        max_time_block.set_extended_time_encoding()
        max_time_block.hashMerkleRoot = max_time_block.calc_merkle_root()
        max_time_block.solve()
        assert_equal(self.nodes[0].submitblock(max_time_block.serialize().hex()), "time-too-new")

        self.log.info("Build a shared chain whose MTP reaches the last 32-bit timestamp")
        block_hashes = self.generate(wallet, 8, sync_fun=self.no_op)
        self.nodes[1].setmocktime(TIME_2106)
        self.nodes[0].setmocktime(TIME_2106)
        block_hashes += self.generate(wallet, 6, sync_fun=self.no_op)
        assert_equal(self.nodes[0].getblockheader(block_hashes[-1])["mediantime"], TIME_2106)

        for block_hash in block_hashes:
            assert_equal(self.nodes[1].submitblock(self.nodes[0].getblock(block_hash, 0)), None)
        assert_equal(self.nodes[1].getbestblockhash(), self.nodes[0].getblockhash(14))

        self.log.info("Continue the chain with an extended 64-bit timestamp")
        self.nodes[0].setmocktime(TIME_2106 + 1)
        extended_block = create_block(tmpl=self.nodes[0].getblocktemplate(NORMAL_GBT_REQUEST_PARAMS))
        assert_equal(extended_block.nTime, TIME_2106 + 1)
        self.solve_with_zero_low_nonce_byte(extended_block)
        extended_block_hex = extended_block.serialize().hex()
        assert_equal(self.nodes[0].submitblock(extended_block_hex), None)
        extended_header = CBlockHeader()
        extended_header.deserialize(BytesIO(bytes.fromhex(extended_block_hex)))
        assert_equal(extended_header.nTime, TIME_2106 + 1)
        assert extended_header.uses_extended_time_encoding()
        assert extended_header.nVersion < 0
        assert_equal(self.nodes[0].getblockheader(extended_block.hash_hex)["time"], TIME_2106 + 1)
        assert_raises_rpc_error(
            -5,
            "gettxoutproof is not supported for extended-header blocks",
            self.nodes[0].gettxoutproof,
            [extended_block.vtx[0].txid_hex],
            extended_block.hash_hex,
        )

        self.log.info("Previous release rejects the extended-time block")
        self.submit_to_previous_release(extended_block_hex)


if __name__ == "__main__":
    Y2106ExtendedTimeTest(__file__).main()

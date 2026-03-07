#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the IPC (multiprocess) Mining interface."""
import asyncio
import time
from contextlib import AsyncExitStack
from io import BytesIO
import platform
from test_framework.blocktools import NULL_OUTPOINT
from test_framework.messages import (
    MAX_BLOCK_WEIGHT,
    CBlockHeader,
    CTransaction,
    CTxIn,
    CTxOut,
    CTxInWitness,
    ser_uint256,
    COIN,
    from_hex,
    msg_headers,
)
from test_framework.script import (
    CScript,
    CScriptNum,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
    assert_not_equal
)
from test_framework.wallet import MiniWallet
from test_framework.p2p import P2PInterface
from test_framework.ipc_util import (
    destroying,
    mining_collect_txs,
    mining_create_block_template,
    load_capnp_modules,
    make_capnp_init_ctx,
    mining_get_block,
    mining_get_coinbase_tx,
    mining_wait_next_template,
    tx_collection_make_template,
    tx_collection_unknown_pos,
    wait_and_do,
)

# Test may be skipped and not have capnp installed
try:
    import capnp  # type: ignore[import] # noqa: F401
except ModuleNotFoundError:
    pass


class IPCMiningTest(BitcoinTestFramework):

    def skip_test_if_missing_module(self):
        self.skip_if_no_ipc()
        self.skip_if_no_py_capnp()

    def set_test_params(self):
        self.num_nodes = 2

    def setup_nodes(self):
        self.extra_init = [{"ipcbind": True}, {"ipcbind": True}]
        super().setup_nodes()
        # Use this function to also load the capnp modules (we cannot use set_test_params for this,
        # as it is being called before knowing whether capnp is available).
        self.capnp_modules = load_capnp_modules(self.config)

    async def build_coinbase_test(self, template, ctx, miniwallet):
        self.log.debug("Build coinbase transaction using getCoinbaseTx()")
        assert template is not None
        coinbase_res = await mining_get_coinbase_tx(template, ctx)
        coinbase_tx = CTransaction()
        coinbase_tx.version = coinbase_res.version
        coinbase_tx.vin = [CTxIn()]
        coinbase_tx.vin[0].prevout = NULL_OUTPOINT
        coinbase_tx.vin[0].nSequence = coinbase_res.sequence

        # Verify there's no dummy extraNonce in the coinbase scriptSig
        current_block_height = self.nodes[0].getchaintips()[0]["height"]
        expected_scriptsig = CScript([CScriptNum(current_block_height + 1)])
        assert_equal(coinbase_res.scriptSigPrefix.hex(), expected_scriptsig.hex())

        # Typically a mining pool appends its name and an extraNonce
        coinbase_tx.vin[0].scriptSig = coinbase_res.scriptSigPrefix

        # We currently always provide a coinbase witness, even for empty
        # blocks, but this may change, so always check:
        has_witness = coinbase_res.witness is not None
        if has_witness:
            coinbase_tx.wit.vtxinwit = [CTxInWitness()]
            coinbase_tx.wit.vtxinwit[0].scriptWitness.stack = [coinbase_res.witness]

        # First output is our payout
        coinbase_tx.vout = [CTxOut()]
        coinbase_tx.vout[0].scriptPubKey = miniwallet.get_output_script()
        coinbase_tx.vout[0].nValue = coinbase_res.blockRewardRemaining
        # Add SegWit OP_RETURN. This is currently always present even for
        # empty blocks, but this may change.
        for output_data in coinbase_res.requiredOutputs:
            output = CTxOut()
            output.deserialize(BytesIO(output_data))
            coinbase_tx.vout.append(output)

        coinbase_tx.nLockTime = coinbase_res.lockTime
        return coinbase_tx

    async def make_mining_ctx(self, node=None):
        """Create IPC context and Mining proxy object."""
        ctx, init = await make_capnp_init_ctx(self, node)
        self.log.debug("Create Mining proxy object")
        mining = init.makeMining(ctx).result
        return ctx, mining

    def run_mining_interface_test(self):
        """Test Mining interface methods."""
        self.log.info("Running Mining interface test")
        block_hash_size = 32
        timeout = 1000.0 # 1000 milliseconds

        async def async_routine():
            ctx, mining = await self.make_mining_ctx()
            blockref = await mining.getTip(ctx)
            current_block_height = self.nodes[0].getchaintips()[0]["height"]
            assert_equal(blockref.result.height, current_block_height)

            self.log.debug("Mine a block")
            newblockref = (await wait_and_do(
                mining.waitTipChanged(ctx, blockref.result.hash, timeout),
                lambda: self.generate(self.nodes[0], 1))).result
            assert_equal(len(newblockref.hash), block_hash_size)
            assert_equal(newblockref.height, current_block_height + 1)
            self.log.debug("Wait for timeout")
            oldblockref = (await mining.waitTipChanged(ctx, newblockref.hash, timeout)).result
            assert_equal(len(newblockref.hash), block_hash_size)
            assert_equal(oldblockref.hash, newblockref.hash)
            assert_equal(oldblockref.height, newblockref.height)

            self.log.debug("interrupt() should abort waitTipChanged()")
            async def wait_for_tip():
                long_timeout = 60000.0  # 1 minute
                result = (await mining.waitTipChanged(ctx, newblockref.hash, long_timeout)).result
                # Unlike a timeout, interrupt() returns an empty BlockRef.
                assert_equal(len(result.hash), 0)
            await wait_and_do(wait_for_tip(), mining.interrupt())

        asyncio.run(capnp.run(async_routine()))

    def run_early_startup_test(self):
        """Make sure mining.createNewBlock safely returns on early startup as
        soon as mining interface is available """
        self.log.info("Running Mining interface early startup test")

        node = self.nodes[0]
        self.stop_node(node.index)
        node.start()

        async def async_routine():
            while True:
                try:
                    ctx, mining = await self.make_mining_ctx()
                    break
                except (ConnectionRefusedError, FileNotFoundError):
                    # Poll quickly to connect as soon as socket becomes
                    # available but without using a lot of CPU
                    await asyncio.sleep(0.005)

            opts = self.capnp_modules['mining'].BlockCreateOptions()
            await mining.createNewBlock(ctx, opts)

        asyncio.run(capnp.run(async_routine()))

        # Reconnect nodes so next tests are happy
        node.wait_for_rpc_connection()
        self.connect_nodes(1, 0)

    def run_block_template_test(self):
        """Test BlockTemplate interface methods."""
        self.log.info("Running BlockTemplate interface test")
        block_header_size = 80
        timeout = 1000.0 # 1000 milliseconds

        async def async_routine():
            ctx, mining = await self.make_mining_ctx()

            async with AsyncExitStack() as stack:
                self.log.debug("createNewBlock() should wait if tip is still updating")
                self.disconnect_nodes(0, 1)
                node1_block_hash = self.generate(self.nodes[1], 1, sync_fun=self.no_op)[0]
                header = from_hex(CBlockHeader(), self.nodes[1].getblockheader(node1_block_hash, False))
                header_only_peer = self.nodes[0].add_p2p_connection(P2PInterface())
                header_only_peer.send_and_ping(msg_headers([header]))
                start = time.time()
                async with destroying((await mining.createNewBlock(ctx, self.default_block_create_options)).result, ctx):
                    pass
                # Lower-bound only: a heavily loaded CI host might still exceed 0.9s
                # even without the cooldown, so this can miss regressions but avoids
                # spurious failures.
                assert_greater_than_or_equal(time.time() - start, 0.9)

                self.log.debug("interrupt() should abort createNewBlock() during cooldown")
                async def create_block():
                    result = await mining.createNewBlock(ctx, self.default_block_create_options)
                    # interrupt() causes createNewBlock to return nullptr
                    assert_equal(result._has("result"), False)

                await wait_and_do(create_block(), mining.interrupt())

                header_only_peer.peer_disconnect()
                self.connect_nodes(0, 1)
                self.sync_all()

                self.log.debug("Create a template")
                template = await mining_create_block_template(mining, stack, ctx, self.default_block_create_options)
                assert template is not None

                self.log.debug("Test some inspectors of Template")
                header = (await template.getBlockHeader(ctx)).result
                assert_equal(len(header), block_header_size)
                block = await mining_get_block(template, ctx)
                current_tip = self.nodes[0].getbestblockhash()
                assert_equal(ser_uint256(block.hashPrevBlock), ser_uint256(int(current_tip, 16)))
                assert_greater_than_or_equal(len(block.vtx), 1)
                txfees = await template.getTxFees(ctx)
                assert_equal(len(txfees.result), 0)
                txsigops = await template.getTxSigops(ctx)
                assert_equal(len(txsigops.result), 0)

                self.log.debug("Wait for a new template")
                waitoptions = self.capnp_modules['mining'].BlockWaitOptions()
                waitoptions.timeout = timeout
                waitoptions.feeThreshold = 1
                template2 = await wait_and_do(
                    mining_wait_next_template(template, stack, ctx, waitoptions),
                    lambda: self.generate(self.nodes[0], 1))
                assert template2 is not None
                block2 = await mining_get_block(template2, ctx)
                assert_equal(len(block2.vtx), 1)

                self.log.debug("Wait for another, but time out")
                template3 = await mining_wait_next_template(template2, stack, ctx, waitoptions)
                assert template3 is None

                self.log.debug("Wait for another, get one after increase in fees in the mempool")
                template4 = await wait_and_do(
                    mining_wait_next_template(template2, stack, ctx, waitoptions),
                    lambda: self.miniwallet.send_self_transfer(fee_rate=10, from_node=self.nodes[0]))
                assert template4 is not None
                block3 = await mining_get_block(template4, ctx)
                assert_equal(len(block3.vtx), 2)

                self.log.debug("Wait again, this should return the same template, since the fee threshold is zero")
                waitoptions.feeThreshold = 0
                template5 = await mining_wait_next_template(template4, stack, ctx, waitoptions)
                assert template5 is not None
                block4 = await mining_get_block(template5, ctx)
                assert_equal(len(block4.vtx), 2)
                waitoptions.feeThreshold = 1

                self.log.debug("Wait for another, get one after increase in fees in the mempool")
                template6 = await wait_and_do(
                    mining_wait_next_template(template5, stack, ctx, waitoptions),
                    lambda: self.miniwallet.send_self_transfer(fee_rate=10, from_node=self.nodes[0]))
                assert template6 is not None
                block4 = await mining_get_block(template6, ctx)
                assert_equal(len(block4.vtx), 3)

                self.log.debug("Wait for another, but time out, since the fee threshold is set now")
                template7 = await mining_wait_next_template(template6, stack, ctx, waitoptions)
                assert template7 is None

                self.log.debug("interruptWait should abort the current wait")
                async def wait_for_block():
                    new_waitoptions = self.capnp_modules['mining'].BlockWaitOptions()
                    new_waitoptions.timeout = timeout * 60 # 1 minute wait
                    new_waitoptions.feeThreshold = 1
                    template7 = await mining_wait_next_template(template6, stack, ctx, new_waitoptions)
                    assert template7 is None
                await wait_and_do(wait_for_block(), template6.interruptWait())

        asyncio.run(capnp.run(async_routine()))

    def run_tx_collection_test(self):
        """Test the TxCollection workflow across two disconnected nodes.

        The test starts with one transaction that is present in both mempools,
        then disconnects the nodes and creates a child transaction that remains
        only in the remote mempool. The remote node proposes a block body by
        creating its own template and sending the ordered wtxid list and
        missing transactions to the local node.

        The local node uses collectTxs()/TxCollection to:
        1. preload any matching mempool transactions,
        2. report which positions are still missing,
        3. accept the remaining transactions from the remote node, and
        4. reconstruct and validate a matching block template locally.

              node0 (local)                     node1 (remote)
            collectTxs(wtxids)        <-     createNewBlock()
            addMissingTxs(rawtxs)     <-     send missing txs
            makeTemplate(prevhash, coinbase)
                                      <-     tip expectations

        The test compares reconstructed blocks, verifies that miner-owned
        metadata getters are unavailable on externally generated templates,
        submits the same solution to both templates, and then syncs the nodes
        to prove they are identical.

        Before reconstruction on the final tip, the remote node advances to a
        competing fork while disconnected so the test can also exercise
        makeTemplate() handling for too-new, competing, and stale prevhashes.
        """
        self.log.info("Running TxCollection test")

        async def async_routine():
            node = self.nodes[0]
            remote_node = self.nodes[1]
            ctx0, mining0 = await self.make_mining_ctx(node)
            ctx1, mining1 = await self.make_mining_ctx(remote_node)
            remote_wallet = MiniWallet(remote_node)

            self.log.debug("collectTxs() should reject duplicate wtxids")
            try:
                await mining0.collectTxs(ctx0, [ser_uint256(1), ser_uint256(1)])
                raise AssertionError("collectTxs unexpectedly accepted duplicate wtxids")
            except capnp.lib.capnp.KjException as e:
                assert_equal(e.description, f"remote exception: std::exception: duplicate wtxid {ser_uint256(1)[::-1].hex()}")
                assert_equal(e.type, "FAILED")

            self.log.debug("Run the main TxCollection workflow across local and remote nodes")
            self.sync_blocks()
            if node.getrawmempool():
                self.log.debug("Clear mempool transactions left over from earlier test phases")
                self.generate(node, 1, sync_fun=self.no_op)
                self.sync_blocks()
            remote_wallet.rescan_utxos()
            self.log.debug("Create a transaction that is shared by both mempools before disconnecting")
            shared_tx = remote_wallet.send_self_transfer(
                from_node=remote_node,
                fee_rate=10,
                confirmed_only=True,
            )
            self.sync_mempools()
            current_tip_info = await mining0.getTip(ctx0)
            current_tip = bytes(current_tip_info.result.hash)

            # Keep the mempools separate for the rest of the test. Remote
            # blocks will be relayed explicitly later instead of reconnecting.
            self.disconnect_nodes(0, 1)

            async with AsyncExitStack() as stack:
                self.log.debug("Create a second transaction that stays only in the remote mempool")
                missing_tx = remote_wallet.send_self_transfer(
                    from_node=remote_node,
                    utxo_to_spend=shared_tx["new_utxo"],
                    fee_rate=10,
                )

                self.log.debug("Remote node builds the reference template that node will reconstruct")
                remote_template = await mining_create_block_template(mining1, stack, ctx1, self.default_block_create_options)
                assert remote_template is not None
                remote_tip_info = await mining1.getTip(ctx1)
                remote_tip = bytes(remote_tip_info.result.hash)
                remote_block = await mining_get_block(remote_template, ctx1)
                assert_equal([tx.wtxid_hex for tx in remote_block.vtx[1:]], [shared_tx["wtxid"], missing_tx["wtxid"]])

                requested_wtxids = [ser_uint256(int(tx.wtxid_hex, 16)) for tx in remote_block.vtx[1:]]
                raw_txs = [tx.serialize() for tx in remote_block.vtx[1:]]
                tx_collection = await mining_collect_txs(mining0, stack, ctx0, requested_wtxids)

                # Reuse the remote reference template to construct a valid
                # coinbase for the early makeTemplate() checks below.
                coinbase = await self.build_coinbase_test(remote_template, ctx1, self.miniwallet)
                coinbase.vout[0].nValue = COIN

                # The first transaction is already in node's mempool, but
                # the child transaction only exists on the disconnected
                # remote node.
                assert_equal(await tx_collection_unknown_pos(tx_collection, ctx0), [1])

                self.log.debug("makeTemplate() should fail while transactions are still missing")
                await tx_collection_make_template(
                    tx_collection, stack, ctx0, current_tip, coinbase.serialize(), reject_reason="missing-txs"
                )

                self.log.debug("Reject unexpected transactions in addMissingTxs(), without undoing earlier additions")
                unexpected_tx = remote_wallet.create_self_transfer(fee_rate=10, confirmed_only=True)
                try:
                    await tx_collection.addMissingTxs(ctx0, [raw_txs[1], unexpected_tx["tx"].serialize()])
                    raise AssertionError("addMissingTxs unexpectedly accepted an unknown wtxid")
                except capnp.lib.capnp.KjException as e:
                    assert_equal(e.description, f"remote exception: std::exception: unexpected wtxid {unexpected_tx['wtxid']}")
                    assert_equal(e.type, "FAILED")
                # The missing transaction should stay added even though the
                # later unexpected one causes the call to fail.
                assert_equal(await tx_collection_unknown_pos(tx_collection, ctx0), [])

                # Mine empty blocks so the reference transactions stay in
                # both mempools while the tip-handling checks run.
                future_block = self.generateblock(
                    remote_node,
                    output="raw(52)",
                    transactions=[],
                    submit=False,
                    sync_fun=self.no_op,
                )["hex"]
                assert_equal(remote_node.submitblock(future_block), None)
                future_tip_info = await mining1.getTip(ctx1)
                future_tip = bytes(future_tip_info.result.hash)

                # Update coinbase BIP34 commitment.
                coinbase.vin[0].scriptSig = CScript([CScriptNum(int(future_tip_info.result.height) + 1)])

                self.log.debug("makeTemplate() should fail before the requested tip arrives")
                await tx_collection_make_template(
                    tx_collection, stack, ctx0, future_tip, coinbase.serialize(), reject_reason="inconclusive-tip-too-new"
                )

                self.log.debug("makeTemplate() should reject an equal-height competing tip")
                self.generate(node, 1, sync_fun=self.no_op)
                fork_tip_info = await mining0.getTip(ctx0)
                fork_tip = bytes(fork_tip_info.result.hash)
                assert_equal(int(fork_tip_info.result.height), int(future_tip_info.result.height))
                assert_not_equal(fork_tip, future_tip)
                await tx_collection_make_template(
                    tx_collection, stack, ctx0, future_tip, coinbase.serialize(), reject_reason="bad-prevblk"
                )

                self.log.debug("Extend the remote chain so the local node can reorg to it")
                final_block = self.generateblock(
                    remote_node,
                    output="raw(52)",
                    transactions=[],
                    submit=False,
                    sync_fun=self.no_op,
                )["hex"]
                assert_equal(remote_node.submitblock(final_block), None)

                self.log.debug("Relay the remote fork blocks and wait for the local tip to catch up")
                assert_equal(node.submitblock(future_block), "inconclusive")
                assert_equal(node.submitblock(final_block), None)
                self.wait_until(lambda: node.getbestblockhash() == remote_node.getbestblockhash())

                self.log.debug("makeTemplate() should reject a stale tip after the reorg")
                await tx_collection_make_template(
                    tx_collection, stack, ctx0, future_tip, coinbase.serialize(), reject_reason="stale-prevblk"
                )

                self.log.debug("Remote node rebuilds the reference template on the new tip")
                remote_template = await mining_create_block_template(mining1, stack, ctx1, self.default_block_create_options)
                assert remote_template is not None
                remote_tip_info = await mining1.getTip(ctx1)
                remote_tip = bytes(remote_tip_info.result.hash)
                remote_block = await mining_get_block(remote_template, ctx1)
                assert_equal([tx.wtxid_hex for tx in remote_block.vtx[1:]], [shared_tx["wtxid"], missing_tx["wtxid"]])

                refreshed_template = await mining_create_block_template(mining0, stack, ctx0, self.default_block_create_options)
                assert refreshed_template is not None
                coinbase = await self.build_coinbase_test(refreshed_template, ctx0, self.miniwallet)
                coinbase.vout[0].nValue = COIN
                template = await tx_collection_make_template(tx_collection, stack, ctx0, remote_tip, coinbase.serialize())
                local_block = await mining_get_block(template, ctx0)

                assert_equal([tx.wtxid_hex for tx in local_block.vtx[1:]], [tx.wtxid_hex for tx in remote_block.vtx[1:]])

                self.log.debug("Externally generated templates should not expose miner-owned metadata")
                for method_name, method in (
                    ("getCoinbaseTx", template.getCoinbaseTx),
                    ("getTxFees", template.getTxFees),
                    ("getTxSigops", template.getTxSigops),
                ):
                    try:
                        await method(ctx0)
                        raise AssertionError(f"{method_name} unexpectedly succeeded on external template")
                    except capnp.lib.capnp.KjException as e:
                        assert_equal(e.description, f"remote exception: std::exception: {method_name} is unavailable for externally generated templates")
                        assert_equal(e.type, "FAILED")

                self.log.debug("Solve the reconstructed block and submit the same solution to both templates")
                local_block.solve()
                version = local_block.nVersion
                time = local_block.nTime
                nonce = local_block.nNonce
                coinbase = local_block.vtx[0].serialize()

                submitted_local = (await template.submitSolution(ctx0, version, time, nonce, coinbase)).result
                assert_equal(submitted_local, True)

                submitted_remote = (await remote_template.submitSolution(ctx1, version, time, nonce, coinbase)).result
                assert_equal(submitted_remote, True)
                assert_equal(node.getbestblockhash(), remote_node.getbestblockhash())

            self.connect_nodes(0, 1)
            self.sync_blocks()

        asyncio.run(capnp.run(async_routine()))
        # Test cleanup
        self.sync_blocks()
        self.miniwallet.rescan_utxos()

    def run_ipc_option_override_test(self):
        self.log.info("Running IPC option override test")
        # Set an absurd reserved weight. `-blockreservedweight` is RPC-only, so
        # with this setting RPC templates would be empty. IPC clients set
        # blockReservedWeight per template request and are unaffected; later in
        # the test the IPC template includes a mempool transaction.
        self.restart_node(0, extra_args=[f"-blockreservedweight={MAX_BLOCK_WEIGHT}"])

        async def async_routine():
            ctx, mining = await self.make_mining_ctx()
            self.miniwallet.send_self_transfer(fee_rate=10, from_node=self.nodes[0])

            async with AsyncExitStack() as stack:
                opts = self.capnp_modules['mining'].BlockCreateOptions()
                template = await mining_create_block_template(mining, stack, ctx, opts)
                assert template is not None
                block = await mining_get_block(template, ctx)
                assert_equal(len(block.vtx), 2)

                self.log.debug("Use absurdly large reserved weight to force an empty template")
                opts.blockReservedWeight = MAX_BLOCK_WEIGHT
                empty_template = await mining_create_block_template(mining, stack, ctx, opts)
                assert empty_template is not None
                empty_block = await mining_get_block(empty_template, ctx)
                assert_equal(len(empty_block.vtx), 1)

            self.log.debug("Enforce minimum reserved weight for IPC clients too")
            opts.blockReservedWeight = 0
            try:
                await mining.createNewBlock(ctx, opts)
                raise AssertionError("createNewBlock unexpectedly succeeded")
            except capnp.lib.capnp.KjException as e:
                if e.description == "remote exception: unknown non-KJ exception of type: kj::Exception":
                    # macOS + REDUCE_EXPORTS bug: Cap'n Proto fails to recognize
                    # its own exception type and returns a generic error instead.
                    # https://github.com/bitcoin/bitcoin/pull/34422#discussion_r2863852691
                    # Assert this only occurs on Darwin until fixed.
                    assert_equal(platform.system(), "Darwin")
                else:
                    assert_equal(e.description, "remote exception: std::exception: block_reserved_weight (0) must be at least 2000 weight units")
                assert_equal(e.type, "FAILED")

        asyncio.run(capnp.run(async_routine()))

    def run_coinbase_and_submission_test(self):
        """Test coinbase construction (getCoinbaseTx) and block submission (submitSolution)."""
        self.log.info("Running coinbase construction and submission test")

        async def async_routine():
            ctx, mining = await self.make_mining_ctx()
            coinbase_wallet = MiniWallet(self.nodes[0], tag_name="coinbase_test")
            coinbase_wallet.rescan_utxos()

            current_block_height = self.nodes[0].getchaintips()[0]["height"]
            check_opts = self.capnp_modules['mining'].BlockCheckOptions()

            async with destroying((await mining.createNewBlock(ctx, self.default_block_create_options)).result, ctx) as template:
                block = await mining_get_block(template, ctx)
                balance = coinbase_wallet.get_balance()
                coinbase = await self.build_coinbase_test(template, ctx, coinbase_wallet)
                # Reduce payout for balance comparison simplicity
                coinbase.vout[0].nValue = COIN
                block.vtx[0] = coinbase
                block.hashMerkleRoot = block.calc_merkle_root()
                original_version = block.nVersion

                self.log.debug("Submit a block with a bad version")
                block.nVersion = 0
                block.solve()
                check = await mining.checkBlock(ctx, block.serialize(), check_opts)
                assert_equal(check.result, False)
                assert_equal(check.reason, "bad-version(0x00000000)")
                submitted = (await template.submitSolution(ctx, block.nVersion, block.nTime, block.nNonce, coinbase.serialize())).result
                assert_equal(submitted, False)
                self.log.debug("Submit a valid block")
                block.nVersion = original_version
                block.solve()

                self.log.debug("First call checkBlock()")
                block_valid = (await mining.checkBlock(ctx, block.serialize(), check_opts)).result
                assert_equal(block_valid, True)

                # The remote template block will be mutated, capture the original:
                remote_block_before = await mining_get_block(template, ctx)

                self.log.debug("Submitted coinbase must include witness")
                assert_not_equal(coinbase.serialize_without_witness().hex(), coinbase.serialize().hex())
                submitted = (await template.submitSolution(ctx, block.nVersion, block.nTime, block.nNonce, coinbase.serialize_without_witness())).result
                assert_equal(submitted, False)

                self.log.debug("Even a rejected submitSolution() mutates the template's block")
                # Can be used by clients to download and inspect the (rejected)
                # reconstructed block.
                remote_block_after = await mining_get_block(template, ctx)
                assert_not_equal(remote_block_before.serialize().hex(), remote_block_after.serialize().hex())

                self.log.debug("Submit again, with the witness")
                submitted = (await template.submitSolution(ctx, block.nVersion, block.nTime, block.nNonce, coinbase.serialize())).result
                assert_equal(submitted, True)

            self.log.debug("Block should propagate")
            # Check that the IPC node actually updates its own chain
            assert_equal(self.nodes[0].getchaintips()[0]["height"], current_block_height + 1)
            # Stalls if a regression causes submitSolution() to accept an invalid block:
            self.sync_all()
            # Check that the other node accepts the block
            assert_equal(self.nodes[0].getchaintips()[0], self.nodes[1].getchaintips()[0])

            coinbase_wallet.rescan_utxos()
            assert_equal(coinbase_wallet.get_balance(), balance + 1)
            self.log.debug("Check block should fail now, since it is a duplicate")
            check = await mining.checkBlock(ctx, block.serialize(), check_opts)
            assert_equal(check.result, False)
            assert_equal(check.reason, "inconclusive-not-best-prevblk")

        asyncio.run(capnp.run(async_routine()))

    def run_test(self):
        self.miniwallet = MiniWallet(self.nodes[0])
        self.default_block_create_options = self.capnp_modules['mining'].BlockCreateOptions()
        self.run_mining_interface_test()
        self.run_early_startup_test()
        self.run_block_template_test()
        self.run_tx_collection_test()
        self.run_coinbase_and_submission_test()
        self.run_ipc_option_override_test()


if __name__ == '__main__':
    IPCMiningTest(__file__).main()

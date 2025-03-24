#!/usr/bin/env python3
# Copyright (c) 2025 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://opensource.org/licenses/mit-license.php.
"""
Tests a vault construction based on OP_CHECKCONTRACTVERIFY.

The vaults are functionally very similar to the ones defined in BIP-345, except that
the withdrawal transaction must send the entire amount to a single P2TR output.
"""

from typing import Optional

from test_framework import key, script
from test_framework.test_framework import BitcoinTestFramework, TestNode
from test_framework.p2p import P2PInterface
from test_framework.wallet import MiniWallet, MiniWalletMode
from test_framework.script import (
    CScript,
    OP_1, OP_CHECKCONTRACTVERIFY, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_DROP,
    OP_DUP, OP_PICK, OP_SWAP, OP_TRUE
)
from test_framework.messages import CTransaction, CTxOut
from test_framework.util import assert_equal, assert_raises_rpc_error

from feature_checkcontractverify import (
    P2TR, AugmentedP2TR, CCV_FLAG_CHECK_INPUT, CCV_FLAG_DEDUCT_OUTPUT_AMOUNT,
    CcvInput, PrivkeyPlaceholder, TapTree, create_tx, NUMS_KEY
)


hot_privkey = key.ECKey()
hot_privkey.set(
    b'y\x88\xe19\x11_\xf6\x19L#\xb7t\x9c\xce\x1c\x08\xf6\xdf\x1a\x01W\xc8\xc1\x07\x8d\xb9\x14\xf1\x91\x89c\x8b', True)
hot_pubkey_xonly = hot_privkey.get_pubkey().get_bytes()[1:]

cold_privkey = key.ECKey()
cold_privkey.set(
    b'\xdcg\xd3\x9f\xc5\x0c/\x82\x06\x01\\T\x8f\xd2\xb6\x90\xddJ\xe5:\xbc\xddJ\rV\x1c\xe2\x07\xb0\xdd7\x89', True)
cold_pubkey_xonly = cold_privkey.get_pubkey().get_bytes()[1:]


class Vault(P2TR):
    """
    A UTXO that can be spent either:
    - with the "recover" clause, sending it to a PT2R output that has cold_pk as the taproot key
    - with the "trigger" clause, sending the entire amount to an Unvaulting output, after providing a 'withdrawal_pk'
    - with the "trigger_and_partially_revault" clause, sending part of the amount to an output with the same script as this Vault, and the rest
      to an Unvaulting output, after providing a 'withdrawal_pk'
    """

    def __init__(self, spend_delay: int, cold_pk: bytes, hot_pk: bytes, *, has_partial_revault=True, has_early_recover=True):
        assert len(cold_pk) == 32 and len(hot_pk) == 32

        self.spend_delay = spend_delay
        self.cold_pk = cold_pk
        self.hot_pk = hot_pk

        unvaulting = Unvaulting(spend_delay, cold_pk)

        self.has_partial_revault = has_partial_revault
        self.has_early_recover = has_early_recover

        # witness: <sig> <withdrawal_pk> <out_i>
        trigger_leaf = ("trigger",
                   CScript([
                       # data and index already on the stack
                       -1, # current input's internal key, i.e. cold_pk
                       unvaulting.get_taptree(),  # taptree
                       0,  # standard flags
                       OP_CHECKCONTRACTVERIFY,

                       hot_pk,
                       OP_CHECKSIG
                   ])
                   )

        # witness: <sig> <withdrawal_pk> <trigger_out_i> <revault_out_i>
        trigger_and_partially_revault_leaf = (
            "trigger_and_partially_revault",
            CScript([
                0, OP_SWAP,   # no data tweak
                -1,  # current input's internal key, i.e. cold_pk
                -1,  # current input's taptweak
                CCV_FLAG_DEDUCT_OUTPUT_AMOUNT,  # revault output
                OP_CHECKCONTRACTVERIFY,

                # data and index already on the stack
                -1,  # pk
                unvaulting.get_taptree(),  # taptree
                0,  # standard flags
                OP_CHECKCONTRACTVERIFY,

                hot_pk,
                OP_CHECKSIG
            ])
        )

        # witness: <out_i>
        recover_leaf = (
            "recover",
            CScript([
                0,  # data
                OP_SWAP,  # <out_i> (from witness)
                cold_pk,  # pk
                0,  # taptree
                0,  # flags
                OP_CHECKCONTRACTVERIFY,
                OP_TRUE
            ])
        )

        super().__init__(cold_pk, [
            trigger_leaf, [trigger_and_partially_revault_leaf, recover_leaf]])


class Unvaulting(AugmentedP2TR):
    """
    A UTXO that can be spent either:
    - with the "recover" clause, sending it to a PT2R output that has cold_pk as the taproot key
    - with the "withdrawal" clause, after a relative timelock of spend_delay blocks, sending the entire amount to a P2TR output that has
      the taproot key 'withdrawal_pk'
    """

    def __init__(self, spend_delay: int, cold_pk: bytes):
        assert len(cold_pk) == 32

        self.spend_delay = spend_delay
        self.cold_pk = cold_pk

        super().__init__(cold_pk)

    def get_scripts(self) -> TapTree:
        # witness: <withdrawal_pk>
        withdraw_leaf = (
            "withdraw",
            CScript([
                # Check withdrawal_pk commitment
                OP_DUP, # data is withdrawal_pk
                -1, # current input
                0, # NUMS (ignored)
                CCV_FLAG_CHECK_INPUT,
                OP_CHECKCONTRACTVERIFY,

                # Check timelock
                self.spend_delay, OP_CHECKSEQUENCEVERIFY, OP_DROP,

                # Check that the transaction output is as expected
                0,  # no data
                0,  # output index
                2, OP_PICK,  # withdrawal_pk
                0,  # no taptweak
                0,  # default flags
                OP_CHECKCONTRACTVERIFY,

                # withdrawal_pk is left on the stack on success
            ])
        )

        # witness: <out_i>
        recover_leaf = (
            "recover",
            CScript([
                0,  # data
                OP_SWAP,  # <out_i> (from witness)
                self.cold_pk,  # pk
                0,  # taptree
                0,  # flags
                OP_CHECKCONTRACTVERIFY,
                OP_TRUE
            ])
        )

        return [withdraw_leaf, recover_leaf]


# We reuse these specs for all the tests
vault_contract = Vault(
    spend_delay=10,
    cold_pk=cold_pubkey_xonly,
    hot_pk=hot_pubkey_xonly
)
unvault_contract = Unvaulting(
    spend_delay=10,
    cold_pk=cold_pubkey_xonly
)


class CheckContractVerifyVaultTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [
            [
                # Use only one script thread to get the exact reject reason for testing
                "-par=1",
                # TODO: figure out changes to standardness rules
                "-acceptnonstdtxn=1",
                # TODO: remove when package relay submission becomes a thing.
                "-minrelaytxfee=0",
                "-blockmintxfee=0",
            ]
        ]
        self.setup_clean_chain = True

    def run_test(self):
        wallet = MiniWallet(self.nodes[0], mode=MiniWalletMode.RAW_OP_TRUE)
        node = self.nodes[0]
        node.add_p2p_connection(P2PInterface())

        # Generate some matured UTXOs to spend into vaults.
        self.generate(wallet, 200)

        # Run the original end-to-end Vault flow.
        self.test_vault_e2e(node, wallet)
        # Test spending two Vault outputs in one transaction.
        self.test_trigger_and_partially_revault(node, wallet)
        # Test spending the Unvaulting output using the 'recover' clause.
        self.test_unvault_recover(node, wallet)

    def test_vault_e2e(
        self,
        node: TestNode,
        wallet: MiniWallet,
    ):
        """
        Demonstrates a simple Vault flow:
         1) Create a Vault output
         2) Trigger into Unvault output
         3) Attempt early withdrawal (fail)
         4) Wait spend_delay blocks
         5) Attempt withdrawal to a wrong pubkey (fail)
         6) Complete the withdrawal
        """
        ######################################
        # Create the Vault UTXO
        ######################################
        vault_amount = 50_000
        vault_txout = CTxOut(
            vault_amount, vault_contract.get_tr_info().scriptPubKey)
        res = wallet.send_to(
            from_node=node,
            scriptPubKey=vault_txout.scriptPubKey,
            amount=vault_txout.nValue
        )
        vault_txid, vault_vout = res["txid"], res["sent_vout"]
        self.generate(node, 1)

        ######################################
        # Step 2: Trigger → Unvault
        ######################################

        withdrawal_pk = b'\x01' * 32
        withdrawal_hijacker_pk = b'\x02' * 32


        tx_trigger = create_tx(
            inputs=[CcvInput(
                vault_txid, vault_vout, vault_amount,
                vault_contract,
                None,
                "trigger",
                # [unvault_signature, withdrawal_pk, out_i]
                [PrivkeyPlaceholder(hot_privkey),
                 withdrawal_pk, script.bn2vch(0)]
            )],
            outputs=[
                unvault_contract.get_tx_out(vault_amount, withdrawal_pk),
            ],
        )

        trigger_txid = self.assert_broadcast_tx(tx_trigger, mine_all=True)

        ######################################
        # Step 3a: Prepare withdrawal
        ######################################

        withdraw_amount = vault_amount

        # No signature is required for this step
        withdrawal_inputs = [CcvInput(
            trigger_txid, 0, withdraw_amount,
            unvault_contract,
            withdrawal_pk,
            "withdraw",
            [withdrawal_pk],
            nSequence=vault_contract.spend_delay
        )]

        tx_withdraw = create_tx(
            inputs=withdrawal_inputs,
            outputs=[
                CTxOut(withdraw_amount, CScript([OP_1, withdrawal_pk]))
            ],
        )

        ######################################
        # Step 3b: Attempt early withdrawal (fail)
        ######################################

        # This should fail, as the timelock is not satisfied yet
        self.assert_broadcast_tx(tx_withdraw, err_msg="non-BIP68-final")

        ######################################
        # Step 4: Wait spend_delay blocks
        ######################################
        self.generate(node, vault_contract.spend_delay)

        ######################################
        # Step 5: Attempt withdrawal to a wrong pubkey
        ######################################
        hijack_withdrawal_inputs = [CcvInput(
            trigger_txid, 0, withdraw_amount,
            unvault_contract,
            withdrawal_hijacker_pk,
            "withdraw",
            [withdrawal_hijacker_pk],
            nSequence=vault_contract.spend_delay
        )]

        tx_hijack_withdraw = create_tx(
            inputs=hijack_withdrawal_inputs,
            outputs=[
                CTxOut(withdraw_amount, CScript([OP_1, withdrawal_hijacker_pk]))
            ],
        )
        self.assert_broadcast_tx(
        tx_hijack_withdraw, err_msg="mandatory-script-verify-flag-failed")

        ######################################
        # Step 6: Complete the withdrawal
        ######################################

    def test_trigger_and_partially_revault(self, node: TestNode, wallet: MiniWallet):
        """
        Test creating two different Vault outputs and spending them together into one Unvaulting output.
        One input uses the 'trigger' clause and the other uses the 'trigger_and_partially_revault' clause.
        """

        withdrawal_pk = b'\x01' * 32

        # Create two Vault outputs with different amounts.
        vault_amount1 = 40_000
        vault_amount2 = 50_000

        withdrawal_amount = 60_000
        revault_amount = vault_amount1 + vault_amount2 - withdrawal_amount

        res1 = wallet.send_to(
            from_node=node,
            scriptPubKey=vault_contract.get_tr_info().scriptPubKey,
            amount=vault_amount1
        )
        vault1_txid, vault1_vout = res1["txid"], res1["sent_vout"]

        res2 = wallet.send_to(
            from_node=node,
            scriptPubKey=vault_contract.get_tr_info().scriptPubKey,
            amount=vault_amount2
        )
        vault2_txid, vault2_vout = res2["txid"], res2["sent_vout"]

        self.generate(node, 1)  # confirm both vault outputs

        # Create a transaction that spends both vault outputs into a single Unvaulting output.
        # For the first input, use the 'trigger' clause.
        # For the second input, use the 'trigger_and_partially_revault' clause.
        tx_trigger = create_tx(
            inputs=[
                CcvInput(
                    vault1_txid, vault1_vout, vault_amount1,
                    vault_contract,
                    None,
                    "trigger",
                    [PrivkeyPlaceholder(hot_privkey),
                     withdrawal_pk, script.bn2vch(0)]
                ),
                CcvInput(
                    vault2_txid, vault2_vout, vault_amount2,
                    vault_contract,
                    None,
                    "trigger_and_partially_revault",
                    [PrivkeyPlaceholder(hot_privkey),
                     withdrawal_pk, script.bn2vch(0), script.bn2vch(1)]
                )
            ],
            outputs=[
                unvault_contract.get_tx_out(withdrawal_amount, withdrawal_pk),
                vault_contract.get_tx_out(revault_amount)
            ],
        )

        self.assert_broadcast_tx(tx_trigger, mine_all=True)

    def test_unvault_recover(self, node: TestNode, wallet: MiniWallet):
        """
        Test spending a Vault output to create an Unvaulting output and then
        spending the Unvaulting output using the 'recover' clause.
        """

        attacker_withdrawal_pk = b'\x01' * 32
        vault_amount = 50_000

        # Create the Vault output.
        vault_txout = CTxOut(
            vault_amount, vault_contract.get_tr_info().scriptPubKey)
        res = wallet.send_to(
            from_node=node,
            scriptPubKey=vault_txout.scriptPubKey,
            amount=vault_txout.nValue
        )
        vault_txid, vault_vout = res["txid"], res["sent_vout"]
        self.generate(node, 1)

        # Attacker compromised hot key and spend the Vault output using the
        # 'trigger' clause to produce an Unvaulting output.
        tx_trigger = create_tx(
            inputs=[CcvInput(
                vault_txid, vault_vout, vault_amount,
                vault_contract,
                None,
                "trigger",
                [PrivkeyPlaceholder(hot_privkey),
                 attacker_withdrawal_pk, script.bn2vch(0)]
            )],
            outputs=[
                unvault_contract.get_tx_out(vault_amount, attacker_withdrawal_pk)
            ],
        )
        unvault_txid = self.assert_broadcast_tx(tx_trigger, mine_all=True)

        # No signature is required for recovery
        inputs = [CcvInput(
            unvault_txid, 0, vault_amount,
            unvault_contract,
            attacker_withdrawal_pk,
            "recover",
            [script.bn2vch(0)]
        )]

        # Recovering to the wrong pubkey should fail.
        tx_recover_wrong = create_tx(
            inputs=inputs,
            outputs=[
                CTxOut(vault_amount, CScript([OP_1, NUMS_KEY]))
            ],
        )
        self.assert_broadcast_tx(
            tx_recover_wrong, err_msg="Mismatching contract data or program")

        # Now correctly spend the Unvaulting output using the 'recover' clause.
        tx_recover = create_tx(
            inputs=inputs,
            outputs=[
                CTxOut(vault_amount, CScript([OP_1, cold_pubkey_xonly]))
            ],
        )
        self.assert_broadcast_tx(tx_recover, mine_all=True)

    # taken from OP_VAULT PR's functional test

    def assert_broadcast_tx(
        self,
        tx: CTransaction,
        mine_all: bool = False,
        err_msg: Optional[str] = None
    ) -> str:
        """
        Broadcast a transaction and facilitate various assertions about how the
        broadcast went.
        """
        node = self.nodes[0]
        txhex = tx.serialize().hex()
        txid = tx.rehash()

        if not err_msg:
            assert_equal(node.sendrawtransaction(txhex), txid)
        else:
            assert_raises_rpc_error(-26, err_msg,
                                    node.sendrawtransaction, txhex)

        if mine_all:
            self.generate(node, 1)
            assert_equal(node.getmempoolinfo()["size"], 0)

        return txid


if __name__ == "__main__":
    CheckContractVerifyVaultTest(__file__).main()

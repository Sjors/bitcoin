// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <core_io.h>
#include <index/txindex.h>
#include <merkleblock.h>
#include <node/txproof.h>
#include <node/blockstorage.h>
#include <primitives/transaction.h>
#include <rpc/blockchain.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <validation.h>

#include <optional>
#include <set>

using node::GetTransaction;
using node::MakeTxProof;
using node::TxProof;
using node::TxProofVerificationResult;
using node::VerifyTxProof;

static UniValue MerklePathToUniv(const std::vector<uint256>& path)
{
    UniValue result{UniValue::VARR};
    for (const uint256& hash : path) {
        result.push_back(hash.GetHex());
    }
    return result;
}

static std::optional<std::vector<uint256>> ParseMerklePath(const UniValue& proofs, const std::string& path, const std::string& key)
{
    const UniValue& merkle_path{proofs.find_value(key)};
    if (merkle_path.isNull()) return std::nullopt;
    if (!merkle_path.isArray()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.%s must be an array", path, key));
    }
    std::vector<uint256> result;
    result.reserve(merkle_path.size());
    for (unsigned int i{0}; i < merkle_path.size(); ++i) {
        result.push_back(ParseHashV(merkle_path[i], strprintf("%s.%s[%u]", path, key, i)));
    }
    return result;
}

static UniValue TxProofTransactionToUniv(const node::TxProofTransaction& transaction)
{
    UniValue proof{UniValue::VOBJ};
    if (transaction.txid_branch) {
        proof.pushKV("txid", MerklePathToUniv(*transaction.txid_branch));
    }
    if (transaction.wtxid_branch) {
        proof.pushKV("wtxid", MerklePathToUniv(*transaction.wtxid_branch));
    }

    UniValue result{UniValue::VOBJ};
    result.pushKV("txid", transaction.txid.GetHex());
    result.pushKV("wtxid", transaction.wtxid.GetHex());
    result.pushKV("pos", transaction.pos);
    result.pushKV("proof", std::move(proof));
    return result;
}

static UniValue TxProofTransactionsToUniv(const std::vector<node::TxProofTransaction>& transactions)
{
    UniValue result{UniValue::VARR};
    for (const auto& transaction : transactions) {
        result.push_back(TxProofTransactionToUniv(transaction));
    }
    return result;
}

static UniValue TxProofToUniv(const TxProof& proof)
{
    UniValue result{UniValue::VOBJ};
    result.pushKV("blockhash", proof.block_hash.GetHex());
    result.pushKV("block_tx_count", proof.block_tx_count);
    result.pushKV("coinbase_tx", EncodeHexTx(*proof.coinbase));
    result.pushKV("transactions", TxProofTransactionsToUniv(proof.transactions));
    return result;
}

static std::optional<TxProof> ParseTxProof(const UniValue& proof)
{
    TxProof result;
    result.block_hash = ParseHashO(proof, "blockhash");
    result.block_tx_count = proof.find_value("block_tx_count").getInt<uint32_t>();

    CMutableTransaction coinbase_mut;
    if (!DecodeHexTx(coinbase_mut, proof.find_value("coinbase_tx").get_str())) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "coinbase_tx must be a serialized transaction");
    }
    result.coinbase = MakeTransactionRef(std::move(coinbase_mut));

    const UniValue& transactions{proof.find_value("transactions")};
    if (!transactions.isArray()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "transactions must be an array");
    }
    if (transactions.size() > 2) {
        return std::nullopt;
    }
    result.transactions.reserve(transactions.size());
    for (unsigned int i{0}; i < transactions.size(); ++i) {
        const UniValue& transaction{transactions[i]};
        if (!transaction.isObject()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("transactions[%u] must be an object", i));
        }

        auto& entry{result.transactions.emplace_back()};
        entry.txid = Txid::FromUint256(ParseHashO(transaction, "txid"));
        entry.wtxid = Wtxid::FromUint256(ParseHashO(transaction, "wtxid"));
        entry.pos = transaction.find_value("pos").getInt<uint32_t>();

        const UniValue& branches{transaction.find_value("proof")};
        if (!branches.isObject()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("transactions[%u].proof must be an object", i));
        }
        const std::string path{strprintf("transactions[%u].proof", i)};
        entry.txid_branch = ParseMerklePath(branches, path, "txid");
        entry.wtxid_branch = ParseMerklePath(branches, path, "wtxid");
        if (!entry.txid_branch && !entry.wtxid_branch) return std::nullopt;
    }
    return result;
}

static UniValue TxProofVerificationResultToUniv(const TxProofVerificationResult& proof)
{
    UniValue transactions{UniValue::VARR};
    for (const auto& transaction : proof.transactions) {
        UniValue entry{UniValue::VOBJ};
        entry.pushKV("pos", transaction.pos);
        if (transaction.txid) {
            entry.pushKV("txid", transaction.txid->GetHex());
        }
        if (transaction.wtxid) {
            entry.pushKV("wtxid", transaction.wtxid->GetHex());
        }
        transactions.push_back(std::move(entry));
    }

    UniValue result{UniValue::VOBJ};
    result.pushKV("blockhash", proof.block_hash.GetHex());
    result.pushKV("block_tx_count", proof.block_tx_count);
    result.pushKV("transactions", std::move(transactions));
    return result;
}

static const CBlockIndex* GetTxProofBlockIndex(ChainstateManager& chainman, const std::set<Txid>& txids, const UniValue& blockhash_param)
{
    const CBlockIndex* pblockindex{nullptr};
    uint256 hash_block;
    if (!blockhash_param.isNull()) {
        LOCK(cs_main);
        hash_block = ParseHashV(blockhash_param, "blockhash");
        pblockindex = chainman.m_blockman.LookupBlockIndex(hash_block);
        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
        return pblockindex;
    }

    {
        LOCK(cs_main);
        Chainstate& active_chainstate = chainman.ActiveChainstate();

        // Loop through txids and try to find which block they're in. Exit loop once a block is found.
        for (const auto& txid : txids) {
            const Coin& coin{AccessByTxid(active_chainstate.CoinsTip(), txid)};
            if (!coin.IsSpent()) {
                pblockindex = active_chainstate.m_chain[coin.nHeight];
                break;
            }
        }
    }

    // Allow txindex to catch up if we need to query it and before we acquire cs_main.
    if (g_txindex && !pblockindex) {
        g_txindex->BlockUntilSyncedToCurrentChain();
    }

    if (pblockindex == nullptr) {
        const CTransactionRef tx = GetTransaction(/*block_index=*/nullptr, /*mempool=*/nullptr, *txids.begin(), chainman.m_blockman, hash_block);
        if (!tx || hash_block.IsNull()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not yet in block");
        }

        LOCK(cs_main);
        pblockindex = chainman.m_blockman.LookupBlockIndex(hash_block);
        if (!pblockindex) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Transaction index corrupt");
        }
    }

    return pblockindex;
}

static RPCMethod gettxproof()
{
    return RPCMethod{
        "gettxproof",
        "Returns a transaction inclusion proof for a transaction in a block.\n"
        "\nThe proof uses plain merkle branches rather than the legacy BIP37 merkleblock encoding.\n"
        "Target transactions are selected by witness transaction id. If the block has a witness\n"
        "commitment, non-coinbase target transactions are proven by wtxid; otherwise they are\n"
        "proven by txid, which is equal to wtxid for those transactions. The coinbase transaction\n"
        "is always included at position 0 so verifiers can prove the presence or absence of the\n"
        "witness commitment. Passing an empty wtxids array returns only this coinbase proof, which\n"
        "is equivalent to requesting the coinbase transaction's wtxid. The wtxids array is reserved\n"
        "for future expansion, but currently accepts at most one element.\n",
        {
            {"wtxids", RPCArg::Type::ARR, RPCArg::Optional::NO, "The witness transaction id to prove. Accepts at most one element. Empty array returns only the coinbase proof",
                {
                    {"wtxid", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A witness transaction id"},
                },
            },
            {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "blockhash", "The block hash the proof links to"},
                {RPCResult::Type::NUM, "block_tx_count", "The number of transactions in the block"},
                {RPCResult::Type::STR_HEX, "coinbase_tx", "The serialized coinbase transaction, hex-encoded with witness data"},
                {RPCResult::Type::ARR, "transactions", "The coinbase proof followed by the target transaction if one was requested", {
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
                        {RPCResult::Type::STR_HEX, "wtxid", "The witness transaction id"},
                        {RPCResult::Type::NUM, "pos", "The transaction position in the block"},
                        {RPCResult::Type::OBJ, "proof", "Merkle branches ordered from leaf to root", {
                            {RPCResult::Type::ARR, "txid", /*optional=*/true, "Branch proving txid against the block header merkle root; present for the coinbase and for non-coinbase targets when the block has no witness commitment", {
                                {RPCResult::Type::STR_HEX, "", "A sibling hash"},
                            }},
                            {RPCResult::Type::ARR, "wtxid", /*optional=*/true, "Branch proving wtxid against the witness merkle root; present for non-coinbase targets when the block has a witness commitment", {
                                {RPCResult::Type::STR_HEX, "", "A sibling hash"},
                            }},
                        }},
                    }},
                }},
            }
        },
        RPCExamples{""},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            std::set<Wtxid> wtxids;
            const UniValue wtxid_values{request.params[0].get_array()};
            for (unsigned int i{0}; i < wtxid_values.size(); ++i) {
                auto inserted{wtxids.insert(Wtxid::FromUint256(ParseHashV(wtxid_values[i], strprintf("wtxids[%u]", i))))};
                if (!inserted.second) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter, duplicated wtxid: %s", wtxid_values[i].get_str()));
                }
            }
            if (wtxids.size() > 1) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Parameter 'wtxids' accepts at most one element");
            }
            std::optional<Wtxid> wtxid;
            if (!wtxids.empty()) {
                wtxid = *wtxids.begin();
            }

            const uint256 block_hash{ParseHashV(request.params[1], "blockhash")};
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            const CBlockIndex* pblockindex{nullptr};
            {
                LOCK(cs_main);
                pblockindex = chainman.m_blockman.LookupBlockIndex(block_hash);
                if (!pblockindex) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
                }
                CheckBlockDataAvailability(chainman.m_blockman, *pblockindex, /*check_for_undo=*/false);
            }
            CBlock block;
            if (!chainman.m_blockman.ReadBlock(block, *pblockindex)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");
            }

            const auto proof{MakeTxProof(block, wtxid)};
            if (!proof) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Not all transactions found in specified block");
            }
            return TxProofToUniv(*proof);
        },
    };
}

static RPCMethod gettxoutproof()
{
    return RPCMethod{
        "gettxoutproof",
        "Returns a hex-encoded proof that \"txid\" was included in a block.\n"
        "\nNOTE: By default this function only works sometimes. This is when there is an\n"
        "unspent output in the utxo for this transaction. To make it always work,\n"
        "you need to maintain a transaction index, using the -txindex command line option or\n"
        "specify the block in which the transaction is included manually (by blockhash).\n",
        {
            {"txids", RPCArg::Type::ARR, RPCArg::Optional::NO, "The txids to filter",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A transaction hash"},
                },
            },
            {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "If specified, looks for txid in the block with this hash"},
        },
        RPCResult{
            RPCResult::Type::STR, "data", "A string that is a serialized, hex-encoded data for the proof."
        },
        RPCExamples{""},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            std::set<Txid> setTxids;
            UniValue txids = request.params[0].get_array();
            if (txids.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Parameter 'txids' cannot be empty");
            }
            for (unsigned int idx = 0; idx < txids.size(); idx++) {
                auto ret{setTxids.insert(Txid::FromUint256(ParseHashV(txids[idx], "txid")))};
                if (!ret.second) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated txid: ") + txids[idx].get_str());
                }
            }

            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            const CBlockIndex* pblockindex{GetTxProofBlockIndex(chainman, setTxids, request.params[1])};

            {
                LOCK(cs_main);
                CheckBlockDataAvailability(chainman.m_blockman, *pblockindex, /*check_for_undo=*/false);
            }
            CBlock block;
            if (!chainman.m_blockman.ReadBlock(block, *pblockindex)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");
            }

            unsigned int ntxFound = 0;
            for (const auto& tx : block.vtx) {
                if (setTxids.contains(tx->GetHash())) {
                    ntxFound++;
                }
            }
            if (ntxFound != setTxids.size()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Not all transactions found in specified or retrieved block");
            }

            DataStream ssMB{};
            CMerkleBlock mb(block, setTxids);
            ssMB << mb;
            std::string strHex = HexStr(ssMB);
            return strHex;
        },
    };
}

static RPCMethod verifytxproof()
{
    return RPCMethod{
        "verifytxproof",
        "Verifies a transaction inclusion proof produced by gettxproof.\n"
        "\nReturns an object with the proven transaction identifiers if the proof is valid, or an empty\n"
        "object if the proof is well-formed but invalid. For non-coinbase targets, blocks with a witness\n"
        "commitment prove the wtxid, and blocks without a witness commitment prove the txid.\n"
        "\nBy default, the block must be in the active chain. Set require_active_chain=false to verify\n"
        "proofs for known stale blocks.\n",
        {
            {"txproof", RPCArg::Type::OBJ, RPCArg::Optional::NO, "The proof object generated by gettxproof",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash the proof links to"},
                    {"block_tx_count", RPCArg::Type::NUM, RPCArg::Optional::NO, "The number of transactions in the block"},
                    {"coinbase_tx", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The serialized coinbase transaction, hex-encoded with witness data"},
                    {"transactions", RPCArg::Type::ARR, RPCArg::Optional::NO, "The coinbase proof followed by the target transaction if one was requested",
                        {
                            {"transaction", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                                    {"wtxid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The witness transaction id"},
                                    {"pos", RPCArg::Type::NUM, RPCArg::Optional::NO, "The transaction position in the block"},
                                    {"proof", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Merkle branches ordered from leaf to root",
                                        {
                                            {"txid", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Branch proving txid against the block header merkle root; present for the coinbase and for non-coinbase targets when the block has no witness commitment",
                                                {
                                                    {"hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A sibling hash"},
                                                },
                                            },
                                            {"wtxid", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Branch proving wtxid against the witness merkle root; present for non-coinbase targets when the block has a witness commitment",
                                                {
                                                    {"hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A sibling hash"},
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
                RPCArgOptions{.oneline_description = "txproof"}},
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "",
                {
                    {"require_active_chain", RPCArg::Type::BOOL, RPCArg::Default{true}, "If true, require the proof's block to be in the active chain"},
                },
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "The proven transaction information if the proof is valid, or an empty object if invalid",
            {
                {RPCResult::Type::STR_HEX, "blockhash", /*optional=*/true, "The block hash this proof links to"},
                {RPCResult::Type::NUM, "block_tx_count", /*optional=*/true, "The number of transactions in the block"},
                {RPCResult::Type::ARR, "transactions", /*optional=*/true, "The proven transaction identifiers", {
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::NUM, "pos", "The transaction position in the block"},
                        {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "The proven transaction id"},
                        {RPCResult::Type::STR_HEX, "wtxid", /*optional=*/true, "The proven witness transaction id"},
                    }},
                }},
            }
        },
        RPCExamples{""},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            const auto proof{ParseTxProof(request.params[0].get_obj())};
            if (!proof) return UniValue{UniValue::VOBJ};
            const UniValue options{request.params[1].isNull() ? UniValue::VOBJ : request.params[1].get_obj()};
            const bool require_active_chain{options["require_active_chain"].isNull() ? true : options["require_active_chain"].get_bool()};

            const CBlockIndex* pindex{nullptr};
            CBlockHeader header;
            uint32_t block_tx_count{0};
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            {
                LOCK(cs_main);
                pindex = chainman.m_blockman.LookupBlockIndex(proof->block_hash);
                if (!pindex || pindex->nTx == 0) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found in chain");
                }
                if (require_active_chain && !chainman.ActiveChain().Contains(*pindex)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found in active chain");
                }
                if (pindex->nTx != proof->block_tx_count) return UniValue{UniValue::VOBJ};
                header = pindex->GetBlockHeader();
                block_tx_count = pindex->nTx;
            }

            const auto verification{VerifyTxProof(*proof, header, block_tx_count)};
            return verification ? TxProofVerificationResultToUniv(*verification) : UniValue{UniValue::VOBJ};
        },
    };
}

static RPCMethod verifytxoutproof()
{
    return RPCMethod{
        "verifytxoutproof",
        "Verifies that a proof points to a transaction in a block, returning the transaction it commits to\n"
        "and throwing an RPC error if the block is not in our best chain\n",
        {
            {"proof", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex-encoded proof generated by gettxoutproof"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The txid(s) which the proof commits to, or empty array if the proof cannot be validated."},
            }
        },
        RPCExamples{""},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            CMerkleBlock merkleBlock;
            SpanReader{ParseHexV(request.params[0], "proof")} >> merkleBlock;

            UniValue res(UniValue::VARR);

            std::vector<Txid> vMatch;
            std::vector<unsigned int> vIndex;
            if (merkleBlock.txn.ExtractMatches(vMatch, vIndex) != merkleBlock.header.hashMerkleRoot)
                return res;

            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            LOCK(cs_main);

            const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(merkleBlock.header.GetHash());
            if (!pindex || !chainman.ActiveChain().Contains(*pindex) || pindex->nTx == 0) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found in chain");
            }

            // Check if proof is valid, only add results if so
            if (pindex->nTx == merkleBlock.txn.GetNumTransactions()) {
                for (const auto& txid : vMatch) {
                    res.push_back(txid.GetHex());
                }
            }

            return res;
        },
    };
}

void RegisterTxoutProofRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"blockchain", &gettxproof},
        {"blockchain", &verifytxproof},
        {"blockchain", &gettxoutproof},
        {"blockchain", &verifytxoutproof},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}

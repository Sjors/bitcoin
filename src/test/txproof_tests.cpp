// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <test/data/txproof.json.h>
#include <test/util/json.h>

#include <core_io.h>
#include <node/txproof.h>
#include <primitives/block.h>
#include <streams.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <optional>
#include <set>
#include <string>
#include <vector>

namespace {

uint256 HashFromHex(const std::string& hex)
{
    const auto hash{uint256::FromHex(hex)};
    BOOST_REQUIRE(hash);
    return *hash;
}

std::vector<uint256> BranchFromJson(const UniValue& proof, const std::string& key)
{
    std::vector<uint256> branch;
    const UniValue& hashes{proof.find_value(key)};
    BOOST_REQUIRE(hashes.isArray());
    branch.reserve(hashes.size());
    for (unsigned int i{0}; i < hashes.size(); ++i) {
        branch.push_back(HashFromHex(hashes[i].get_str()));
    }
    return branch;
}

std::optional<std::vector<uint256>> OptionalBranchFromJson(const UniValue& proof, const std::string& key)
{
    const UniValue& hashes{proof.find_value(key)};
    if (hashes.isNull()) return std::nullopt;
    return BranchFromJson(proof, key);
}

node::TxProofTransaction TransactionFromJson(const UniValue& transaction)
{
    node::TxProofTransaction result;
    result.txid = Txid::FromUint256(HashFromHex(transaction["txid"].get_str()));
    result.wtxid = Wtxid::FromUint256(HashFromHex(transaction["wtxid"].get_str()));
    result.pos = transaction["pos"].getInt<uint32_t>();

    const UniValue& proof{transaction["proof"]};
    BOOST_REQUIRE(proof.isObject());
    result.txid_branch = OptionalBranchFromJson(proof, "txid");
    result.wtxid_branch = OptionalBranchFromJson(proof, "wtxid");
    return result;
}

node::TxProof ProofFromJson(const UniValue& proof)
{
    node::TxProof result;
    result.block_hash = HashFromHex(proof["blockhash"].get_str());
    result.block_tx_count = proof["block_tx_count"].getInt<uint32_t>();

    CMutableTransaction coinbase_mut;
    BOOST_REQUIRE(DecodeHexTx(coinbase_mut, proof["coinbase_tx"].get_str()));
    result.coinbase = MakeTransactionRef(std::move(coinbase_mut));

    const UniValue& transactions{proof["transactions"]};
    BOOST_REQUIRE(transactions.isArray());
    result.transactions.reserve(transactions.size());
    for (const UniValue& transaction : transactions.getValues()) {
        result.transactions.push_back(TransactionFromJson(transaction));
    }
    return result;
}

UniValue BranchToJson(const std::vector<uint256>& branch)
{
    UniValue result{UniValue::VARR};
    for (const auto& hash : branch) {
        result.push_back(hash.GetHex());
    }
    return result;
}

UniValue TransactionToJson(const node::TxProofTransaction& transaction)
{
    UniValue proof{UniValue::VOBJ};
    if (transaction.txid_branch) {
        proof.pushKV("txid", BranchToJson(*transaction.txid_branch));
    }
    if (transaction.wtxid_branch) {
        proof.pushKV("wtxid", BranchToJson(*transaction.wtxid_branch));
    }

    UniValue result{UniValue::VOBJ};
    result.pushKV("txid", transaction.txid.GetHex());
    result.pushKV("wtxid", transaction.wtxid.GetHex());
    result.pushKV("pos", transaction.pos);
    result.pushKV("proof", std::move(proof));
    return result;
}

UniValue ProofToJson(const node::TxProof& proof)
{
    UniValue transactions{UniValue::VARR};
    for (const auto& transaction : proof.transactions) {
        transactions.push_back(TransactionToJson(transaction));
    }

    UniValue result{UniValue::VOBJ};
    result.pushKV("blockhash", proof.block_hash.GetHex());
    result.pushKV("block_tx_count", proof.block_tx_count);
    result.pushKV("coinbase_tx", EncodeHexTx(*proof.coinbase));
    result.pushKV("transactions", std::move(transactions));
    return result;
}

void CheckInvalid(const node::TxProof& proof, const CBlock& block)
{
    BOOST_CHECK(!node::VerifyTxProof(proof, static_cast<const CBlockHeader&>(block), static_cast<uint32_t>(block.vtx.size())));
}

} // namespace

BOOST_AUTO_TEST_SUITE(txproof_tests)

BOOST_AUTO_TEST_CASE(mainnet_vectors)
{
    const UniValue blocks{read_json(json_tests::txproof)};
    for (const UniValue& block_vector : blocks.getValues()) {
        CBlock block;
        BOOST_REQUIRE(DecodeHexBlk(block, block_vector["block_hex"].get_str()));

        for (const UniValue& case_vector : block_vector["cases"].getValues()) {
            const UniValue& proof_json{case_vector["proof"]};
            const UniValue& transactions{proof_json["transactions"]};
            BOOST_REQUIRE(transactions.isArray());
            BOOST_REQUIRE(!transactions.empty());
            const Wtxid wtxid{Wtxid::FromUint256(HashFromHex(transactions[transactions.size() - 1]["wtxid"].get_str()))};

            const auto generated_proof{node::MakeTxProof(block, wtxid)};
            BOOST_REQUIRE(generated_proof);
            BOOST_CHECK_EQUAL(ProofToJson(*generated_proof).write(), proof_json.write());

            const node::TxProof proof{ProofFromJson(proof_json)};
            const auto verification{node::VerifyTxProof(proof, static_cast<const CBlockHeader&>(block), static_cast<uint32_t>(block.vtx.size()))};
            BOOST_REQUIRE(verification);
            BOOST_CHECK_EQUAL(verification->block_hash.GetHex(), proof.block_hash.GetHex());
            BOOST_CHECK_EQUAL(verification->block_tx_count, proof.block_tx_count);
            BOOST_CHECK_EQUAL(verification->transactions.size(), proof.transactions.size());
            for (const auto& transaction : verification->transactions) {
                BOOST_CHECK(transaction.txid || transaction.wtxid);
            }

            auto invalid{proof};
            invalid.block_tx_count += 1;
            CheckInvalid(invalid, block);

            invalid = proof;
            invalid.transactions.front().pos = proof.block_tx_count;
            CheckInvalid(invalid, block);

            if (proof.transactions.front().txid_branch && !proof.transactions.front().txid_branch->empty()) {
                invalid = proof;
                (*invalid.transactions.front().txid_branch)[0] = uint256::ONE;
                CheckInvalid(invalid, block);
            }

            if (proof.transactions.size() > 1) {
                const auto& target{proof.transactions.back()};
                if (target.txid_branch && !target.txid_branch->empty()) {
                    invalid = proof;
                    (*invalid.transactions.back().txid_branch)[0] = uint256::ONE;
                    CheckInvalid(invalid, block);
                }
                if (target.wtxid_branch && !target.wtxid_branch->empty()) {
                    invalid = proof;
                    (*invalid.transactions.back().wtxid_branch)[0] = uint256::ONE;
                    CheckInvalid(invalid, block);
                }
            } else {
                invalid = proof;
                invalid.transactions.front().wtxid_branch = std::vector<uint256>{};
                CheckInvalid(invalid, block);
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()

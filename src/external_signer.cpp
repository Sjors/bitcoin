// Copyright (c) 2018-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <external_signer.h>

#include <common/run_command.h>
#include <core_io.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <pubkey.h>
#include <random.h>
#include <script/interpreter.h>
#include <script/keyorigin.h>
#include <script/script.h>
#include <streams.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/result.h>
#include <util/strencodings.h>
#include <util/subprocess.h>
#include <util/translation.h>
#include <util/vector.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

ExternalSigner::ExternalSigner(std::vector<std::string> command, std::string chain, std::string fingerprint, std::string name)
    : m_command{std::move(command)}, m_chain{std::move(chain)}, m_fingerprint{std::move(fingerprint)}, m_name{std::move(name)} {}

std::vector<std::string> ExternalSigner::NetworkArg() const
{
    return {"--chain", m_chain};
}

bool ExternalSigner::Enumerate(const std::string& command, std::vector<ExternalSigner>& signers, const std::string& chain)
{
    // Call <command> enumerate
    std::vector<std::string> cmd_args = Cat(subprocess::util::split(command), {"enumerate"});

    const UniValue result = RunCommandParseJSON(cmd_args, "");
    if (!result.isArray()) {
        throw std::runtime_error(strprintf("'%s' received invalid response, expected array of signers", command));
    }
    for (const UniValue& signer : result.getValues()) {
        // Check for error
        const UniValue& error = signer.find_value("error");
        if (!error.isNull()) {
            if (!error.isStr()) {
                throw std::runtime_error(strprintf("'%s' error", command));
            }
            throw std::runtime_error(strprintf("'%s' error: %s", command, error.getValStr()));
        }
        // Check if fingerprint is present
        const UniValue& fingerprint = signer.find_value("fingerprint");
        if (fingerprint.isNull()) {
            throw std::runtime_error(strprintf("'%s' received invalid response, missing signer fingerprint", command));
        }
        const std::string& fingerprintStr{fingerprint.get_str()};
        if (fingerprintStr.size() != 8 || !IsHex(fingerprintStr)) {
            throw std::runtime_error(strprintf("'%s' received invalid fingerprint, must be 8 hex characters", command));
        }
        // Skip duplicate signer
        bool duplicate = false;
        for (const ExternalSigner& signer : signers) {
            if (signer.m_fingerprint.compare(fingerprintStr) == 0) duplicate = true;
        }
        if (duplicate) continue;
        std::string name;
        const UniValue& model_field = signer.find_value("model");
        if (model_field.isStr() && model_field.getValStr() != "") {
            name += model_field.getValStr();
        }
        signers.emplace_back(subprocess::util::split(command), chain, fingerprintStr, name);
    }
    return true;
}

UniValue ExternalSigner::DisplayAddress(const std::string& descriptor) const
{
    return RunCommandParseJSON(Cat(m_command, Cat(Cat({"--fingerprint", m_fingerprint}, NetworkArg()), {"displayaddress", "--desc", descriptor})), "");
}

UniValue ExternalSigner::GetDescriptors(const int account)
{
    return RunCommandParseJSON(Cat(m_command, Cat(Cat({"--fingerprint", m_fingerprint}, NetworkArg()), {"getdescriptors", "--account", strprintf("%d", account)})), "");
}

//! Find a sighash type used by the signer that doesn't commit to all outputs;
//! a signature with SIGHASH_NONE or SIGHASH_SINGLE would let anyone alter
//! them. SIGHASH_ANYONECANPAY is acceptable, since it only permits adding
//! inputs, which does not affect us.
static std::optional<int32_t> FindUnsafeSighashType(const PartiallySignedTransaction& psbtx)
{
    std::vector<int32_t> sighash_types;
    for (const PSBTInput& input : psbtx.inputs) {
        if (input.sighash_type) sighash_types.push_back(*input.sighash_type);
        for (const auto& [_, sig] : input.partial_sigs) {
            if (!sig.second.empty()) sighash_types.push_back(sig.second.back());
        }
        // A 64 byte taproot signature implies SIGHASH_DEFAULT, 65 bytes
        // carries an explicit sighash type in the last byte
        if (input.m_tap_key_sig.size() == 65) sighash_types.push_back(input.m_tap_key_sig.back());
        for (const auto& [_, sig] : input.m_tap_script_sigs) {
            if (sig.size() == 65) sighash_types.push_back(sig.back());
        }
    }

    for (const int32_t sighash_type : sighash_types) {
        const int32_t base_sighash_type{sighash_type & ~SIGHASH_ANYONECANPAY};
        if (base_sighash_type != SIGHASH_DEFAULT && base_sighash_type != SIGHASH_ALL) return sighash_type;
    }
    return std::nullopt;
}

namespace {
bool CheckAntiExfilResponse(const PartiallySignedTransaction& request, const PartiallySignedTransaction& response, std::string& error);
} // namespace

bool ExternalSigner::SignTransaction(PartiallySignedTransaction& psbtx, std::string& error, bool require_anti_exfil)
{
    return require_anti_exfil ? SignTransactionAntiExfil(psbtx, error) : SignTransactionRound(psbtx, error);
}

bool ExternalSigner::SignTransactionRound(PartiallySignedTransaction& psbtx, std::string& error, bool check_anti_exfil)
{
    // Serialize the PSBT
    DataStream ssTx{};
    ssTx << psbtx;
    // parse ExternalSigner master fingerprint
    std::vector<unsigned char> parsed_m_fingerprint = ParseHex(m_fingerprint);
    // Check if signer fingerprint matches any input master key fingerprint
    auto matches_signer_fingerprint = [&](const PSBTInput& input) {
        for (const auto& entry : input.hd_keypaths) {
            if (std::ranges::equal(parsed_m_fingerprint, entry.second.fingerprint)) return true;
        }
        for (const auto& entry : input.m_tap_bip32_paths) {
            if (std::ranges::equal(parsed_m_fingerprint, entry.second.second.fingerprint)) return true;
        }
        return false;
    };

    if (!std::any_of(psbtx.inputs.begin(), psbtx.inputs.end(), matches_signer_fingerprint)) {
        error = "Signer fingerprint " + m_fingerprint + " does not match any of the inputs:\n" + EncodeBase64(ssTx.str());
        return false;
    }

    const std::vector<std::string> command = Cat(m_command, Cat({"--stdin", "--fingerprint", m_fingerprint}, NetworkArg()));
    const std::string stdinStr = "signtx " + EncodeBase64(ssTx.str());

    const UniValue signer_result = RunCommandParseJSON(command, stdinStr);

    if (signer_result.find_value("error").isStr()) {
        error = signer_result.find_value("error").get_str();
        return false;
    }

    if (!signer_result.find_value("psbt").isStr()) {
        error = "Unexpected result from signer";
        return false;
    }

    util::Result<PartiallySignedTransaction> signer_psbtx = DecodeBase64PSBT(signer_result.find_value("psbt").get_str());
    if (!signer_psbtx) {
        error = strprintf("TX decode failed %s", util::ErrorString(signer_psbtx).original);
        return false;
    }

    if (signer_psbtx->GetVersion() != psbtx.GetVersion()) {
        error = strprintf("Signer returned PSBT version %u, expected %u", signer_psbtx->GetVersion(), psbtx.GetVersion());
        return false;
    }

    // Finalized inputs hide the signatures from the sighash checks below.
    if (std::ranges::any_of(signer_psbtx->inputs, PSBTInputSigned)) {
        error = "Signer returned a PSBT with finalized inputs";
        return false;
    }

    if (const std::optional<int32_t> sighash{FindUnsafeSighashType(*signer_psbtx)}) {
        const std::string sighash_str{SighashToStr(*sighash)};
        error = strprintf("Signer used an unsafe sighash type: %s", sighash_str.empty() ? "unknown" : sighash_str);
        return false;
    }

    // Validate the raw reply before Merge can retain our value on conflicts or
    // fill omitted fields. Anti-exfil transcript rules are stricter than those
    // of a general-purpose PSBT combiner.
    if (check_anti_exfil && !CheckAntiExfilResponse(psbtx, *signer_psbtx, error)) return false;

    if (!psbtx.Merge(*signer_psbtx)) {
        error = "Signer returned a PSBT for a different transaction";
        return false;
    }

    return true;
}


namespace {
//! Provisional BIP-EXFIL proprietary input keys: fc 02 "ae" subtype outputkey.
PSBTProprietary AntiExfilField(uint8_t subtype, const XOnlyPubKey& pubkey, std::span<const unsigned char> value = {})
{
    std::vector<unsigned char> key{0xfc, 2, 'a', 'e', subtype};
    key.insert(key.end(), pubkey.begin(), pubkey.end());
    return PSBTProprietary{.subtype = subtype, .identifier = {'a', 'e'}, .key = std::move(key), .value = {value.begin(), value.end()}};
}

std::vector<unsigned char> AntiExfilValue(const PSBTInput& input, uint8_t subtype, const XOnlyPubKey& pubkey)
{
    const auto it = input.m_proprietary.find(AntiExfilField(subtype, pubkey));
    return it == input.m_proprietary.end() ? std::vector<unsigned char>{} : it->value;
}

bool CheckAntiExfilResponse(const PartiallySignedTransaction& request, const PartiallySignedTransaction& response, std::string& error)
{
    const auto request_tx = request.GetUnsignedTx();
    const auto response_tx = response.GetUnsignedTx();
    if (!request_tx || !response_tx || request_tx->GetHash() != response_tx->GetHash()) {
        error = "Anti-exfil signer changed the unsigned transaction";
        return false;
    }
    const auto has_ae = [](const auto& fields) {
        return std::ranges::any_of(fields, [](const auto& field) { return field.identifier == std::vector<unsigned char>{'a', 'e'}; });
    };
    if (has_ae(response.m_proprietary) || std::ranges::any_of(response.outputs, [&](const auto& output) { return has_ae(output.m_proprietary); })) {
        error = "Anti-exfil fields are only permitted in input maps";
        return false;
    }
    for (size_t i = 0; i < request.inputs.size(); ++i) {
        const auto& original = request.inputs[i];
        const auto& returned = response.inputs[i];
        CTxOut expected_utxo;
        CTxOut returned_utxo;
        if (!original.GetUTXO(expected_utxo) || !returned.GetUTXO(returned_utxo) || returned_utxo != expected_utxo ||
            (!returned.witness_utxo.IsNull() && returned.witness_utxo != expected_utxo)) {
            error = "Anti-exfil signer changed or omitted input UTXO data";
            return false;
        }
        // The UTXO and complete unsigned transaction, not returned derivation
        // metadata, determine the actual signing key and signature message.
        const bool taproot = expected_utxo.scriptPubKey.IsPayToTaproot();
        const XOnlyPubKey pubkey = taproot ? XOnlyPubKey{std::span{expected_utxo.scriptPubKey}.subspan(2)} : XOnlyPubKey{};
        const auto commitment_key = AntiExfilField(0, pubkey);
        const auto nonce_key = AntiExfilField(1, pubkey);
        const auto entropy_key = AntiExfilField(2, pubkey);
        const auto original_commitment = original.m_proprietary.find(commitment_key);
        const auto original_nonce = original.m_proprietary.find(nonce_key);
        const auto original_entropy = original.m_proprietary.find(entropy_key);
        const bool target = taproot && original_commitment != original.m_proprietary.end();
        const bool reveal = original_entropy != original.m_proprietary.end();
        for (const auto& field : returned.m_proprietary) {
            if (field.identifier != std::vector<unsigned char>{'a', 'e'}) continue;
            if (!target || (field.key != commitment_key.key && field.key != nonce_key.key && field.key != entropy_key.key)) {
                error = "Anti-exfil signer returned an unexpected transcript field";
                return false;
            }
        }
        if (returned.partial_sigs != original.partial_sigs || returned.m_tap_script_sigs != original.m_tap_script_sigs ||
            ((!target || !reveal) && returned.m_tap_key_sig != original.m_tap_key_sig)) {
            error = reveal ? "Anti-exfil signer returned an unexpected signature" : "Anti-exfil signer returned a signature before the host reveal";
            return false;
        }
        if (!target) continue;
        if (returned.sighash_type.value_or(SIGHASH_DEFAULT) != original.sighash_type.value_or(SIGHASH_DEFAULT)) {
            error = "Anti-exfil signer changed the requested sighash type";
            return false;
        }
        const auto returned_commitment = returned.m_proprietary.find(commitment_key);
        const auto returned_nonce = returned.m_proprietary.find(nonce_key);
        const auto returned_entropy = returned.m_proprietary.find(entropy_key);
        if (returned_commitment == returned.m_proprietary.end() || returned_commitment->value != original_commitment->value) {
            error = "Anti-exfil signer changed or omitted the host commitment";
            return false;
        }
        if (returned_nonce == returned.m_proprietary.end() || returned_nonce->value.size() != 33 || !CPubKey{returned_nonce->value}.IsFullyValid()) {
            error = "Anti-exfil signer returned no valid nonce commitment";
            return false;
        }
        if (reveal) {
            if (original_nonce == original.m_proprietary.end() || returned_nonce->value != original_nonce->value ||
                returned_entropy == returned.m_proprietary.end() || returned_entropy->value != original_entropy->value) {
                error = "Anti-exfil signer changed or omitted the host reveal transcript";
                return false;
            }
        } else if (returned_entropy != returned.m_proprietary.end()) {
            // Field presence is forbidden, including a field with an empty value.
            error = "Anti-exfil signer returned host entropy before the host reveal";
            return false;
        }
    }
    return true;
}

struct AntiExfilRequest {
    size_t index;
    XOnlyPubKey pubkey;
    uint256 message;
    int hash_type;
    std::array<unsigned char, 32> entropy;
    std::array<unsigned char, 32> commitment;
    std::vector<unsigned char> nonce;
};
} // namespace

bool ExternalSigner::SignTransactionAntiExfil(PartiallySignedTransaction& psbtx, std::string& error)
{
    // Keep the caller's PSBT unchanged unless the entire exchange succeeds. The
    // device may abort selectively, so never automatically retry with new entropy.
    PartiallySignedTransaction request{psbtx};
    const auto tx = request.GetUnsignedTx();
    const auto txdata = PrecomputePSBTData(request);
    if (!tx || !txdata) {
        error = "Anti-exfil requires complete transaction and UTXO data";
        return false;
    }
    const auto fingerprint = ParseHex(m_fingerprint);
    std::vector<AntiExfilRequest> targets;
    for (size_t i = 0; i < request.inputs.size(); ++i) {
        auto& input = request.inputs[i];
        for (const auto& field : input.m_proprietary) {
            if (field.identifier == std::vector<unsigned char>{'a', 'e'}) {
                error = "Anti-exfil request already contains a transcript";
                return false;
            }
        }
        const bool ours = std::ranges::any_of(input.m_tap_bip32_paths, [&](const auto& entry) {
            return std::ranges::equal(fingerprint, entry.second.second.fingerprint);
        });
        const bool legacy_ours = std::ranges::any_of(input.hd_keypaths, [&](const auto& entry) {
            return std::ranges::equal(fingerprint, entry.second.fingerprint);
        });
        if (PSBTInputSigned(input) || !input.m_tap_key_sig.empty()) continue;
        if (!ours && !legacy_ours) continue;
        CTxOut utxo;
        if (!input.GetUTXO(utxo) || !utxo.scriptPubKey.IsPayToTaproot() || !input.m_tap_script_sigs.empty()) {
            error = "Anti-exfil supports only unsigned Taproot key-path inputs";
            return false;
        }
        const int hash_type = input.sighash_type.value_or(SIGHASH_DEFAULT);
        if (hash_type != SIGHASH_DEFAULT && hash_type != SIGHASH_ALL) {
            error = "Anti-exfil requires SIGHASH_DEFAULT or SIGHASH_ALL";
            return false;
        }
        AntiExfilRequest target{.index = i, .pubkey = XOnlyPubKey{std::span{utxo.scriptPubKey}.subspan(2)}, .message = {}, .hash_type = hash_type, .entropy = {}, .commitment = {}, .nonce = {}};
        ScriptExecutionData execdata;
        execdata.m_annex_init = true;
        execdata.m_annex_present = false;
        if (!SignatureHashSchnorr(target.message, execdata, *tx, i, hash_type, SigVersion::TAPROOT, *txdata, MissingDataBehavior::FAIL)) {
            error = "Anti-exfil could not compute the Taproot signature hash";
            return false;
        }
        while (true) {
            GetStrongRandBytes(target.entropy);
            if (const auto commitment = CreateAntiExfilCommitment(target.entropy)) {
                target.commitment = *commitment;
                break;
            }
        }
        input.m_proprietary.insert(AntiExfilField(0, target.pubkey, target.commitment));
        // Make an omitted v2 sequence explicit before merging signer responses.
        if (!input.sequence) input.sequence = tx->vin[i].nSequence;
        targets.push_back(std::move(target));
    }
    // Another ScriptPubKeyMan, or an earlier unfinalized signing call, may
    // already have supplied every key signature. Do not start a new session
    // or fail simply because there is nothing left for this signer to do.
    if (targets.empty()) return true;

    PartiallySignedTransaction round_one{request};
    if (!SignTransactionRound(round_one, error, /*check_anti_exfil=*/true)) return false;
    for (size_t i = 0; i < request.inputs.size(); ++i) {
        if (round_one.inputs[i].m_tap_key_sig != request.inputs[i].m_tap_key_sig ||
            round_one.inputs[i].m_tap_script_sigs != request.inputs[i].m_tap_script_sigs ||
            round_one.inputs[i].partial_sigs != request.inputs[i].partial_sigs) {
            error = "Anti-exfil signer returned a signature before the host reveal";
            return false;
        }
    }
    for (auto& target : targets) {
        target.nonce = AntiExfilValue(round_one.inputs[target.index], 1, target.pubkey);
        const CPubKey nonce{target.nonce};
        if (target.nonce.size() != 33 || !nonce.IsFullyValid() || !AntiExfilValue(round_one.inputs[target.index], 2, target.pubkey).empty()) {
            error = "Anti-exfil signer returned no valid nonce commitment";
            return false;
        }
        request.inputs[target.index].m_proprietary.insert(AntiExfilField(1, target.pubkey, target.nonce));
        request.inputs[target.index].m_proprietary.insert(AntiExfilField(2, target.pubkey, target.entropy));
    }

    PartiallySignedTransaction round_two{request};
    try {
        if (!SignTransactionRound(round_two, error, /*check_anti_exfil=*/true)) {
            error = "Anti-exfil interrupted after nonce commitment; do not repeatedly retry with fresh randomness: " + error;
            return false;
        }
    } catch (const std::exception& exception) {
        // Process failures and malformed JSON also occur after the signer has
        // learned the opening. Preserve the selective-abort warning for them.
        error = "Anti-exfil interrupted after nonce commitment; do not repeatedly retry with fresh randomness: " + std::string{exception.what()};
        return false;
    }
    // Only copy verified signatures back. Do not persist host entropy or any
    // other device-supplied PSBT metadata in the caller's transaction.
    for (const auto& target : targets) {
        const auto& signature = round_two.inputs[target.index].m_tap_key_sig;
        if ((target.hash_type == SIGHASH_DEFAULT && signature.size() != 64) ||
            (target.hash_type == SIGHASH_ALL && (signature.size() != 65 || signature.back() != SIGHASH_ALL)) ||
            !target.pubkey.VerifySchnorrAntiExfil(target.message, std::span{signature}.first(std::min<size_t>(64, signature.size())), target.entropy, target.nonce)) {
            error = "Anti-exfil signature or nonce proof failed; do not repeatedly retry with fresh randomness";
            return false;
        }
    }
    for (const auto& target : targets) psbtx.inputs[target.index].m_tap_key_sig = round_two.inputs[target.index].m_tap_key_sig;
    return true;
}

// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <common/args.h>
#include <common/system.h>
#include <external_signer.h>
#include <node/types.h>
#include <util/strencodings.h>
#include <wallet/external_signer_scriptpubkeyman.h>

#include <iostream>
#include <key_io.h>
#include <memory>
#include <stdexcept>
#include <string>
#include <univalue.h>
#include <utility>
#include <vector>

using common::PSBTError;

namespace wallet {
std::unique_ptr<ExternalSignerScriptPubKeyMan> ExternalSignerScriptPubKeyMan::LoadFromStorage(WalletStorage& storage, WalletDescriptor& descriptor, int64_t keypool_size, const KeyMap& keys, const CryptedKeyMap& ckeys)
{
    return std::unique_ptr<ExternalSignerScriptPubKeyMan>(new ExternalSignerScriptPubKeyMan(storage, descriptor, keypool_size, keys, ckeys));
}

std::unique_ptr<ExternalSignerScriptPubKeyMan> ExternalSignerScriptPubKeyMan::CreateFromImport(WalletStorage& storage, WalletDescriptor& descriptor, int64_t keypool_size, const FlatSigningProvider& provider)
{
    auto spkm = std::unique_ptr<ExternalSignerScriptPubKeyMan>(new ExternalSignerScriptPubKeyMan(storage, descriptor, keypool_size));
    if (auto res = spkm->UpdateWalletDescriptor(descriptor, provider); !res) {
        throw std::runtime_error(util::ErrorString(res).original);
    }
    return spkm;
}

std::unique_ptr<ExternalSignerScriptPubKeyMan> ExternalSignerScriptPubKeyMan::CreateNew(WalletStorage& storage, WalletBatch& batch, int64_t keypool_size, std::unique_ptr<Descriptor> desc)
{
    auto spkm = std::unique_ptr<ExternalSignerScriptPubKeyMan>(new ExternalSignerScriptPubKeyMan(storage, keypool_size));

    LOCK(spkm->cs_desc_man);
    assert(storage.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));
    assert(storage.IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER));

    int64_t creation_time = GetTime();

    // Make the descriptor
    WalletDescriptor w_desc(std::move(desc), creation_time, 0, 0, 0);
    spkm->m_wallet_descriptor = w_desc;

    // Store the descriptor
    if (!batch.WriteDescriptor(spkm->GetID(), spkm->m_wallet_descriptor)) {
        throw std::runtime_error(std::string(__func__) + ": writing descriptor failed");
    }

    // TopUp
    spkm->TopUpWithDB(batch);

    storage.UnsetBlankWalletFlag(batch);
    return spkm;
}

 util::Result<ExternalSigner> ExternalSignerScriptPubKeyMan::GetExternalSigner() {
    const std::string command = gArgs.GetArg("-signer", "");
    if (command == "") return util::Error{Untranslated("restart bitcoind with -signer=<cmd>")};
    std::vector<ExternalSigner> signers;
    ExternalSigner::Enumerate(command, signers, Params().GetChainTypeString());
    if (signers.empty()) return util::Error{Untranslated("No external signers found")};
    // TODO: add fingerprint argument instead of failing in case of multiple signers.
    if (signers.size() > 1) return util::Error{Untranslated("More than one external signer found. Please connect only one at a time.")};
    return signers[0];
}

util::Result<void> ExternalSignerScriptPubKeyMan::DisplayAddress(const CTxDestination& dest, const ExternalSigner &signer) const
{
    // TODO: avoid the need to infer a descriptor from inside a descriptor wallet
    const CScript& scriptPubKey = GetScriptForDestination(dest);
    auto provider = GetSolvingProvider(scriptPubKey);
    auto descriptor = InferDescriptor(scriptPubKey, *provider);

    const UniValue& result = signer.DisplayAddress(descriptor->ToString());

    const UniValue& error = result.find_value("error");
    if (error.isStr()) return util::Error{strprintf(_("Signer returned error: %s"), error.getValStr())};

    const UniValue& ret_address = result.find_value("address");
    if (!ret_address.isStr()) return util::Error{_("Signer did not echo address")};

    if (ret_address.getValStr() != EncodeDestination(dest)) {
        return util::Error{strprintf(_("Signer echoed unexpected address %s"), ret_address.getValStr())};
    }

    return util::Result<void>();
}

util::Result<void> ExternalSignerScriptPubKeyMan::DisplayAddressPolicy(const CTxDestination& dest,
                                                                       const ExternalSigner& signer,
                                                                       const std::string& name,
                                                                       const std::string& descriptor_template,
                                                                       const std::vector<std::string>& keys_info,
                                                                       const std::optional<std::string>& hmac,
                                                                       bool change,
                                                                       uint32_t index) const
{
    const UniValue& result{signer.DisplayAddressPolicy(name, descriptor_template, keys_info, hmac, change, index)};

    const UniValue& error = result.find_value("error");
    if (error.isStr()) return util::Error{strprintf(_("Signer returned error: %s"), error.getValStr())};

    const UniValue& ret_address = result.find_value("address");
    if (!ret_address.isStr()) return util::Error{_("Signer did not echo address")};

    // Compare the echoed address by witness program rather than by string.
    // The Ledger Bitcoin app, for instance, encodes addresses with the
    // testnet "tb1..." HRP even when -chain=regtest is in effect, so a
    // strict EncodeDestination comparison would spuriously fail. Try each
    // known chain's params and accept the echo if any of them decodes to
    // the same scriptPubKey as the requested destination.
    const CScript expected_script{GetScriptForDestination(dest)};
    bool address_matches{false};
    for (const ChainType chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::TESTNET4, ChainType::SIGNET, ChainType::REGTEST}) {
        std::unique_ptr<const CChainParams> cp = CreateChainParams(gArgs, chain);
        std::string err;
        const CTxDestination cand = DecodeDestination(ret_address.getValStr(), *cp, err);
        if (IsValidDestination(cand) && GetScriptForDestination(cand) == expected_script) {
            address_matches = true;
            break;
        }
    }
    if (!address_matches) {
        return util::Error{strprintf(_("Signer echoed unexpected address %s"), ret_address.getValStr())};
    }

    return util::Result<void>();
}

// If sign is true, transaction must previously have been filled
std::optional<PSBTError> ExternalSignerScriptPubKeyMan::FillPSBT(PartiallySignedTransaction& psbt, const PrecomputedTransactionData& txdata, const common::PSBTFillOptions& options, int* n_signed) const
{
    if (!options.sign) {
        return DescriptorScriptPubKeyMan::FillPSBT(psbt, txdata, options, n_signed);
    }

    // Already complete if every input is now signed
    bool complete = true;
    for (const auto& input : psbt.inputs) {
        complete &= PSBTInputSigned(input);
    }
    if (complete) return {};

    auto signer{GetExternalSigner()};
    if (!signer) {
        LogWarning("%s", util::ErrorString(signer).original);
        return PSBTError::EXTERNAL_SIGNER_NOT_FOUND;
    }

    std::string failure_reason;
    if(!signer->SignTransaction(psbt, failure_reason)) {
        LogWarning("Failed to sign: %s\n", failure_reason);
        return PSBTError::EXTERNAL_SIGNER_FAILED;
    }
    if (options.finalize) FinalizePSBT(psbt); // This won't work in a multisig setup
    return {};
}

util::Result<std::optional<std::string>> ExternalSignerScriptPubKeyMan::RegisterPolicy(const ExternalSigner& signer,
                                                                                       const std::string& name,
                                                                                       const std::string& descriptor_template,
                                                                                       const std::vector<std::string>& keys_info) const
{
    const UniValue& result{signer.RegisterPolicy(name, descriptor_template, keys_info)};

    const UniValue& error = result.find_value("error");
    if (error.isStr()) return util::Error{strprintf(_("Signer returned error: %s"), error.getValStr())};

    const UniValue& ret_hmac = result.find_value("hmac");
    if (ret_hmac.isNull()) return std::optional<std::string>{};
    if (!ret_hmac.isStr()) return util::Error{_("Signer returned invalid hmac field")};
    const std::string hmac{ret_hmac.getValStr()};
    if (!IsHex(hmac)) return util::Error{strprintf(_("Signer return invalid hmac: %s"), hmac)};

    return std::optional<std::string>{hmac};
}

} // namespace wallet

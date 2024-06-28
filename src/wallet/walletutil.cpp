// Copyright (c) 2017-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/walletutil.h>

#include <chainparams.h>
#include <common/args.h>
#include <key_io.h>
#include <logging.h>
#include <outputtype.h>
#include <script/signingprovider.h>
#include <script/solver.h>

namespace wallet {
fs::path GetWalletDir()
{
    fs::path path;

    if (gArgs.IsArgSet("-walletdir")) {
        path = gArgs.GetPathArg("-walletdir");
        if (!fs::is_directory(path)) {
            // If the path specified doesn't exist, we return the deliberately
            // invalid empty string.
            path = "";
        }
    } else {
        path = gArgs.GetDataDirNet();
        // If a wallets directory exists, use that, otherwise default to GetDataDir
        if (fs::is_directory(path / "wallets")) {
            path /= "wallets";
        }
    }

    return path;
}

bool IsFeatureSupported(int wallet_version, int feature_version)
{
    return wallet_version >= feature_version;
}

WalletFeature GetClosestWalletFeature(int version)
{
    static constexpr std::array wallet_features{FEATURE_LATEST, FEATURE_PRE_SPLIT_KEYPOOL, FEATURE_NO_DEFAULT_KEY, FEATURE_HD_SPLIT, FEATURE_HD, FEATURE_COMPRPUBKEY, FEATURE_WALLETCRYPT, FEATURE_BASE};
    for (const WalletFeature& wf : wallet_features) {
        if (version >= wf) return wf;
    }
    return static_cast<WalletFeature>(0);
}

WalletDescriptor GenerateWalletDescriptor(const CExtKey& master_key, const OutputType& addr_type, bool internal, std::vector<std::pair<CKey, CPubKey>>& out_keys)
{
    int64_t creation_time = GetTime();

    std::string xpub = EncodeExtPubKey(master_key.Neuter());

    // Build descriptor string
    std::string desc_prefix;
    std::string desc_suffix = "/*)";
    switch (addr_type) {
    case OutputType::LEGACY: {
        desc_prefix = "pkh(" + xpub + "/44h";
        break;
    }
    case OutputType::P2SH_SEGWIT: {
        desc_prefix = "sh(wpkh(" + xpub + "/49h";
        desc_suffix += ")";
        break;
    }
    case OutputType::BECH32: {
        desc_prefix = "wpkh(" + xpub + "/84h";
        break;
    }
    case OutputType::BECH32M: {
        desc_prefix = "tr(" + xpub + "/86h";
        break;
    }
    case OutputType::SILENT_PAYMENT: {
        unsigned int hardened = 0x80000000;
        // Derive the spend key at m/352h/0h/0h/0h/0
        std::vector<uint32_t> spend_key_path = {352 | hardened, 0 | hardened, 0 | hardened, 0 | hardened, 0};
        // Derive the scan key at m/352h/0h/0h/1h/0
        std::vector<uint32_t> scan_key_path = {352 | hardened, 0 | hardened, 0 | hardened, 1 | hardened, 0};

        CExtKey spend_key = master_key;
        for (uint32_t i : spend_key_path) {
            if (!spend_key.Derive(spend_key, i)) {
                throw std::runtime_error("Unable to derive silent payments spend key");
            }
        }

        CExtKey scan_key = master_key;
        for (uint32_t i : scan_key_path) {
            if (!scan_key.Derive(scan_key, i)) {
                throw std::runtime_error("Unable to derive silent payments scan key");
            }
        }

        // Add the derived keys
        out_keys.emplace_back(spend_key.key, spend_key.key.GetPubKey());
        out_keys.emplace_back(scan_key.key, scan_key.key.GetPubKey());

        SpPubKey sppub_key(scan_key.key, spend_key.key.GetPubKey());
        std::string sppub = EncodeSpPubKey(sppub_key);
        std::string desc_str = "sp("+ sppub +")";
        FlatSigningProvider keys;
        std::string error;
        std::unique_ptr<Descriptor> desc = Parse(desc_str, keys, error, false);
        WalletDescriptor w_desc(std::move(desc), creation_time, 0, 0, 1); // Start with next_index = 1 because 0 is reserved for change
        return w_desc;
    }
    case OutputType::UNKNOWN: {
        // We should never have a DescriptorScriptPubKeyMan for an UNKNOWN OutputType,
        // so if we get to this point something is wrong
        assert(false);
    }
    } // no default case, so the compiler can warn about missing cases
    assert(!desc_prefix.empty());

    // Mainnet derives at 0', testnet and regtest derive at 1'
    if (Params().IsTestChain()) {
        desc_prefix += "/1h";
    } else {
        desc_prefix += "/0h";
    }

    std::string internal_path = internal ? "/1" : "/0";
    std::string desc_str = desc_prefix + "/0h" + internal_path + desc_suffix;
    out_keys.emplace_back(master_key.key, master_key.key.GetPubKey());

    // Make the descriptor
    FlatSigningProvider keys;
    std::string error;
    std::unique_ptr<Descriptor> desc = Parse(desc_str, keys, error, false);
    WalletDescriptor w_desc(std::move(desc), creation_time, 0, 0, 0);
    return w_desc;
}

std::optional<std::pair<std::vector<XOnlyPubKey>, BIP352::PubTweakData>> GetSilentPaymentsData(const CTransaction& tx, const std::map<COutPoint, Coin>& spent_coins)
{
    std::vector<XOnlyPubKey> output_keys;
    for (const CTxOut& txout : tx.vout) {
        std::vector<std::vector<unsigned char>> solutions;
        TxoutType type = Solver(txout.scriptPubKey, solutions);
        if (type == TxoutType::WITNESS_V1_TAPROOT) {
            output_keys.emplace_back(solutions[0]);
        } else if (type == TxoutType::WITNESS_UNKNOWN) {
            // Cannot have outputs with unknown witness versions
            return std::nullopt;
        }
    }

    // Must have at least one taproot output
    if (output_keys.size() == 0) return std::nullopt;

    auto public_data = BIP352::GetSilentPaymentsPublicData(tx.vin, spent_coins);
    if (!public_data.has_value()) return std::nullopt;

    return std::make_pair(output_keys, *public_data);
}

std::optional<SpPubKey> GetSpPubKeyFrom(std::shared_ptr<Descriptor> desc)
{
    if (desc->GetOutputType() != OutputType::SILENT_PAYMENT) {
        return std::nullopt;
    }
    FlatSigningProvider out_keys;
    std::vector<CScript> out_scripts;
    FlatSigningProvider provider;
    if (!desc->Expand(0, provider, out_scripts, out_keys)) {
        return std::nullopt;
    }
    assert(out_keys.sppubkeys.size() == 1);
    SpPubKey sppubkey = out_keys.sppubkeys.begin()->second;
    return sppubkey;
}

} // namespace wallet

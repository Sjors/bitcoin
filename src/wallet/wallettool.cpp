// Copyright (c) 2016-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <wallet/wallettool.h>

#include <algorithm>
#include <common/args.h>
#include <key_io.h>
#include <script/descriptor.h>
#include <univalue.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/translation.h>
#include <wallet/dump.h>
#include <wallet/encryptedbackup.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>
#include <wallet/walletutil.h>

namespace wallet {
namespace WalletTool {

// The standard wallet deleter function blocks on the validation interface
// queue, which doesn't exist for the bitcoin-wallet. Define our own
// deleter here.
static void WalletToolReleaseWallet(CWallet* wallet)
{
    wallet->WalletLogPrintf("Releasing wallet\n");
    wallet->Close();
    delete wallet;
}

static void WalletCreate(CWallet* wallet_instance, uint64_t wallet_creation_flags)
{
    LOCK(wallet_instance->cs_wallet);

    wallet_instance->InitWalletFlags(wallet_creation_flags);

    Assert(wallet_instance->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));
    wallet_instance->SetupDescriptorScriptPubKeyMans();

    tfm::format(std::cout, "Topping up keypool...\n");
    wallet_instance->TopUpKeyPool();
}

static std::shared_ptr<CWallet> MakeWallet(const std::string& name, const fs::path& path, DatabaseOptions options)
{
    DatabaseStatus status;
    bilingual_str error;
    std::unique_ptr<WalletDatabase> database = MakeDatabase(path, options, status, error);
    if (!database) {
        tfm::format(std::cerr, "%s\n", error.original);
        return nullptr;
    }

    // dummy chain interface
    std::shared_ptr<CWallet> wallet_instance{new CWallet(/*chain=*/nullptr, name, std::move(database)), WalletToolReleaseWallet};
    DBErrors load_wallet_ret;
    try {
        load_wallet_ret = wallet_instance->LoadWallet();
    } catch (const std::runtime_error&) {
        tfm::format(std::cerr, "Error loading %s. Is wallet being used by another process?\n", name);
        return nullptr;
    }

    if (load_wallet_ret != DBErrors::LOAD_OK) {
        if (load_wallet_ret == DBErrors::CORRUPT) {
            tfm::format(std::cerr, "Error loading %s: Wallet corrupted", name);
            return nullptr;
        } else if (load_wallet_ret == DBErrors::NONCRITICAL_ERROR) {
            tfm::format(std::cerr, "Error reading %s! All keys read correctly, but transaction data"
                            " or address book entries might be missing or incorrect.",
                name);
        } else if (load_wallet_ret == DBErrors::TOO_NEW) {
            tfm::format(std::cerr, "Error loading %s: Wallet requires newer version of %s",
                name, CLIENT_NAME);
            return nullptr;
        } else if (load_wallet_ret == DBErrors::NEED_REWRITE) {
            tfm::format(std::cerr, "Wallet needed to be rewritten: restart %s to complete", CLIENT_NAME);
            return nullptr;
        } else if (load_wallet_ret == DBErrors::NEED_RESCAN) {
            tfm::format(std::cerr, "Error reading %s! Some transaction data might be missing or"
                           " incorrect. Wallet requires a rescan.",
                name);
        } else {
            tfm::format(std::cerr, "Error loading %s", name);
            return nullptr;
        }
    }

    if (options.require_create) WalletCreate(wallet_instance.get(), options.create_flags);

    return wallet_instance;
}

static void WalletShowInfo(CWallet* wallet_instance)
{
    LOCK(wallet_instance->cs_wallet);

    tfm::format(std::cout, "Wallet info\n===========\n");
    tfm::format(std::cout, "Name: %s\n", wallet_instance->GetName());
    tfm::format(std::cout, "Format: %s\n", wallet_instance->GetDatabase().Format());
    tfm::format(std::cout, "Descriptors: %s\n", wallet_instance->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS) ? "yes" : "no");
    tfm::format(std::cout, "Encrypted: %s\n", wallet_instance->HasEncryptionKeys() ? "yes" : "no");
    tfm::format(std::cout, "HD (hd seed available): %s\n", wallet_instance->IsHDEnabled() ? "yes" : "no");
    tfm::format(std::cout, "Keypool Size: %u\n", wallet_instance->GetKeyPoolSize());
    tfm::format(std::cout, "Transactions: %zu\n", wallet_instance->mapWallet.size());
    tfm::format(std::cout, "Address Book: %zu\n", wallet_instance->m_address_book.size());
}

bool ExecuteWalletToolFunc(const ArgsManager& args, const std::string& command)
{
    if (args.IsArgSet("-dumpfile") && command != "dump" && command != "createfromdump") {
        tfm::format(std::cerr, "The -dumpfile option can only be used with the \"dump\" and \"createfromdump\" commands.\n");
        return false;
    }
    if (command == "create" && !args.IsArgSet("-wallet")) {
        tfm::format(std::cerr, "Wallet name must be provided when creating a new wallet.\n");
        return false;
    }
    const std::string name = args.GetArg("-wallet", "");
    const fs::path path = fsbridge::AbsPathJoin(GetWalletDir(), fs::PathFromString(name));

    if (command == "create") {
        DatabaseOptions options;
        ReadDatabaseArgs(args, options);
        options.require_create = true;
        options.create_flags |= WALLET_FLAG_DESCRIPTORS;
        options.require_format = DatabaseFormat::SQLITE;

        const std::shared_ptr<CWallet> wallet_instance = MakeWallet(name, path, options);
        if (wallet_instance) {
            WalletShowInfo(wallet_instance.get());
            wallet_instance->Close();
        }
    } else if (command == "info") {
        DatabaseOptions options;
        ReadDatabaseArgs(args, options);
        options.require_existing = true;
        const std::shared_ptr<CWallet> wallet_instance = MakeWallet(name, path, options);
        if (!wallet_instance) return false;
        WalletShowInfo(wallet_instance.get());
        wallet_instance->Close();
    } else if (command == "dump") {
        DatabaseOptions options;
        ReadDatabaseArgs(args, options);
        options.require_existing = true;
        DatabaseStatus status;

        if (IsBDBFile(BDBDataFile(path))) {
            options.require_format = DatabaseFormat::BERKELEY_RO;
        }

        bilingual_str error;
        std::unique_ptr<WalletDatabase> database = MakeDatabase(path, options, status, error);
        if (!database) {
            tfm::format(std::cerr, "%s\n", error.original);
            return false;
        }

        bool ret = DumpWallet(args, *database, error);
        if (!ret && !error.empty()) {
            tfm::format(std::cerr, "%s\n", error.original);
            return ret;
        }
        tfm::format(std::cout, "The dumpfile may contain private keys. To ensure the safety of your Bitcoin, do not share the dumpfile.\n");
        return ret;
    } else if (command == "createfromdump") {
        bilingual_str error;
        std::vector<bilingual_str> warnings;
        bool ret = CreateFromDump(args, name, path, error, warnings);
        for (const auto& warning : warnings) {
            tfm::format(std::cout, "%s\n", warning.original);
        }
        if (!ret && !error.empty()) {
            tfm::format(std::cerr, "%s\n", error.original);
        }
        return ret;
    } else if (command == "encryptbackup") {
        // Encrypt wallet descriptors using BIP-XXXX encrypted backup format
        if (!args.IsArgSet("-wallet")) {
            tfm::format(std::cerr, "Wallet name must be provided for encryptbackup.\n");
            return false;
        }

        DatabaseOptions options;
        ReadDatabaseArgs(args, options);
        options.require_existing = true;
        const std::shared_ptr<CWallet> wallet_instance = MakeWallet(name, path, options);
        if (!wallet_instance) return false;

        LOCK(wallet_instance->cs_wallet);

        // Collect all descriptors from the wallet in listdescriptors format
        // This format preserves origin info and can be used with importdescriptors
        std::vector<std::pair<std::string, WalletDescriptorInfo>> all_descriptors;

        const auto active_spk_mans = wallet_instance->GetActiveScriptPubKeyMans();

        for (const auto& spk_man : wallet_instance->GetAllScriptPubKeyMans()) {
            auto desc_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
            if (desc_spk_man) {
                LOCK(desc_spk_man->cs_desc_man);
                std::string desc_str;
                // Use GetDescriptorString to preserve origin info
                if (!desc_spk_man->GetDescriptorString(desc_str, /*priv=*/false)) {
                    tfm::format(std::cerr, "Failed to get descriptor string.\n");
                    wallet_instance->Close();
                    return false;
                }

                const auto& wallet_desc = desc_spk_man->GetWalletDescriptor();
                const bool is_range = wallet_desc.descriptor->IsRange();

                // Build descriptor info
                WalletDescriptorInfo info{
                    desc_str,
                    wallet_desc.creation_time,
                    active_spk_mans.contains(desc_spk_man),
                    wallet_instance->IsInternalScriptPubKeyMan(desc_spk_man),
                    is_range ? std::optional(std::make_pair(wallet_desc.range_start, wallet_desc.range_end)) : std::nullopt,
                    wallet_desc.next_index
                };
                all_descriptors.emplace_back(desc_str, std::move(info));
            }
        }

        if (all_descriptors.empty()) {
            tfm::format(std::cerr, "No descriptors found in wallet.\n");
            wallet_instance->Close();
            return false;
        }

        // Sort by descriptor string for deterministic ordering
        std::sort(all_descriptors.begin(), all_descriptors.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });

        // Build the output array and select primary descriptor (first when sorted)
        UniValue descriptors_arr(UniValue::VARR);
        std::string primary_descriptor = all_descriptors[0].first;
        for (const auto& [desc_str, info] : all_descriptors) {
            descriptors_arr.push_back(DescriptorInfoToUniValue(info));
        }

        // Build plaintext as JSON array (importdescriptors format)
        std::string plaintext_str = descriptors_arr.write();
        std::vector<uint8_t> plaintext(plaintext_str.begin(), plaintext_str.end());

        // Create backup content metadata
        EncryptedBackupContent content;
        content.type = ContentType::BIP_NUMBER;
        content.bip_number = BIP_DESCRIPTORS;

        // Create the encrypted backup
        auto backup_result = CreateEncryptedBackup(primary_descriptor, plaintext, content, {});
        if (!backup_result) {
            tfm::format(std::cerr, "Failed to create encrypted backup: %s\n",
                        util::ErrorString(backup_result).original);
            wallet_instance->Close();
            return false;
        }

        // Output as base64
        std::string base64_backup = EncodeEncryptedBackupBase64(*backup_result);
        tfm::format(std::cout, "%s\n", base64_backup);

        wallet_instance->Close();
    } else if (command == "decryptbackup") {
        // Decrypt an encrypted backup using a provided extended public key
        if (!args.IsArgSet("-pubkey")) {
            tfm::format(std::cerr, "Extended public key must be provided via -pubkey for decryptbackup.\n");
            return false;
        }

        std::string pubkey_str = args.GetArg("-pubkey", "");
        CExtPubKey ext_pubkey = DecodeExtPubKey(pubkey_str);
        if (!ext_pubkey.pubkey.IsValid()) {
            tfm::format(std::cerr, "Invalid extended public key: %s\n", pubkey_str);
            return false;
        }

        // Read base64 backup from stdin
        std::string base64_input;
        std::getline(std::cin, base64_input);
        if (base64_input.empty()) {
            tfm::format(std::cerr, "No backup data provided on stdin.\n");
            return false;
        }

        // Decode the backup
        auto backup_result = DecodeEncryptedBackupBase64(base64_input);
        if (!backup_result) {
            tfm::format(std::cerr, "Failed to decode backup: %s\n",
                        util::ErrorString(backup_result).original);
            return false;
        }

        // Normalize xpub to x-only pubkey for decryption
        uint256 xonly_key = NormalizeToXOnly(ext_pubkey);

        // Try to decrypt using this key
        auto decrypted = DecryptBackupWithKey(*backup_result, xonly_key);
        if (!decrypted) {
            tfm::format(std::cerr, "Failed to decrypt backup: provided key does not match any recipient.\n");
            return false;
        }

        // Output the decrypted content as JSON (importdescriptors-compatible format)
        std::string plaintext(decrypted->begin(), decrypted->end());
        tfm::format(std::cout, "%s\n", plaintext);
    } else {
        tfm::format(std::cerr, "Invalid command: %s\n", command);
        return false;
    }

    return true;
}
} // namespace WalletTool
} // namespace wallet

// Copyright (c) 2016-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/wallettool.h>

#include <common/args.h>
#include <interfaces/wallet.h>
#include <univalue.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/translation.h>
#include <wallet/context.h>
#include <wallet/dump.h>
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
    std::vector<bilingual_str> warnings;
    std::unique_ptr<WalletDatabase> database = MakeDatabase(path, options, status, error);
    if (!database) {
        tfm::format(std::cerr, "%s\n", error.original);
        return nullptr;
    }

    // dummy chain interface
    std::shared_ptr<CWallet> wallet_instance{new CWallet(/*chain=*/nullptr, name, std::move(database)), WalletToolReleaseWallet};
    DBErrors load_wallet_ret;
    try {
        load_wallet_ret = wallet_instance->PopulateWalletFromDB(error, warnings);
    } catch (const std::runtime_error&) {
        tfm::format(std::cerr, "Error loading %s. Is wallet being used by another process?\n", name);
        return nullptr;
    }

    if (!error.empty()) {
        tfm::format(std::cerr, "%s", error.original);
    }

    for (const auto &warning : warnings) {
        tfm::format(std::cerr, "%s", warning.original);
    }

    if (load_wallet_ret != DBErrors::LOAD_OK && load_wallet_ret != DBErrors::NONCRITICAL_ERROR && load_wallet_ret != DBErrors::NEED_RESCAN) {
        return nullptr;
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
    {
        std::vector<std::string> details;
        if (!args.CheckCommandOptions(command, &details)) {
            tfm::format(std::cerr, "Error: Invalid arguments provided:\n%s\n", util::MakeUnorderedList(details));
            return false;
        }
    }
    if ((command == "create" || command == "createfromdump") && !args.IsArgSet("-wallet")) {
        tfm::format(std::cerr, "Wallet name must be provided when creating a new wallet.\n");
        return false;
    }
    const std::string name = args.GetArg("-wallet", "");
    util::Result<fs::path> path_res = GetWalletPath(name);
    if (!path_res) {
        tfm::format(std::cerr, "%s\n", util::ErrorString(path_res).original);
        return false;
    }
    const fs::path& path = *path_res;

    if (command == "create") {
        if (name.empty()) {
            tfm::format(std::cerr, "Wallet name cannot be empty\n");
            return false;
        }
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
        if (!args.IsArgSet("-wallet")) {
            tfm::format(std::cerr, "Wallet name must be provided for encryptbackup.\n");
            return false;
        }

        DatabaseOptions options;
        ReadDatabaseArgs(args, options);
        options.require_existing = true;
        const std::shared_ptr<CWallet> wallet_instance = MakeWallet(name, path, options);
        if (!wallet_instance) return false;

        WalletContext context;
        auto wallet_interface{interfaces::MakeWallet(context, wallet_instance)};
        auto backup_result{wallet_interface->createEncryptedDescriptorBackup()};
        if (!backup_result) {
            tfm::format(std::cerr, "%s\n", util::ErrorString(backup_result).original);
            wallet_instance->Close();
            return false;
        }

        tfm::format(std::cout, "%s\n", *backup_result);
        wallet_instance->Close();
    } else if (command == "decryptbackup") {
        if (!args.IsArgSet("-pubkey")) {
            tfm::format(std::cerr, "Extended public key must be provided via -pubkey for decryptbackup.\n");
            return false;
        }

        std::string base64_input;
        std::getline(std::cin, base64_input);
        if (base64_input.empty()) {
            tfm::format(std::cerr, "No backup data provided on stdin.\n");
            return false;
        }

        auto wallet_backup{interfaces::MakeWalletBackup()};
        auto decrypted{wallet_backup->decryptEncryptedDescriptorBackup(base64_input, args.GetArg("-pubkey", ""))};
        if (!decrypted) {
            tfm::format(std::cerr, "%s\n", util::ErrorString(decrypted).original);
            return false;
        }

        std::string plaintext(decrypted->begin(), decrypted->end());
        tfm::format(std::cout, "%s\n", plaintext);
    } else if (command == "inspectbackup") {
        std::string base64_input;
        std::getline(std::cin, base64_input);
        if (base64_input.empty()) {
            tfm::format(std::cerr, "No backup data provided on stdin.\n");
            return false;
        }

        auto wallet_backup{interfaces::MakeWalletBackup()};
        auto metadata{wallet_backup->getEncryptedDescriptorBackupMetadata(base64_input)};
        if (!metadata) {
            tfm::format(std::cerr, "%s\n", util::ErrorString(metadata).original);
            return false;
        }

        UniValue result(UniValue::VOBJ);
        result.pushKV("version", static_cast<int>(metadata->version));
        result.pushKV("recipients", static_cast<int>(metadata->recipient_count));
        result.pushKV("encryption", metadata->encryption);

        UniValue paths_arr(UniValue::VARR);
        for (const auto& path : metadata->derivation_paths) {
            paths_arr.push_back(path);
        }
        result.pushKV("derivation_paths", paths_arr);

        tfm::format(std::cout, "%s\n", result.write(2));
    } else {
        tfm::format(std::cerr, "Invalid command: %s\n", command);
        return false;
    }

    return true;
}
} // namespace WalletTool
} // namespace wallet

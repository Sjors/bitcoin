// Copyright (c) 2016-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/wallettool.h>

#include <common/args.h>
#include <key_io.h>
#include <primitives/transaction.h>
#include <script/descriptor.h>
#include <univalue.h>
#include <util/bip32.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <util/translation.h>
#include <wallet/dump.h>
#include <wallet/receive.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>
#include <wallet/walletutil.h>

#include <fstream>
#include <list>
#include <limits>
#include <optional>
#include <set>
#include <string_view>
#include <vector>

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

static bool GetLabelsPath(const ArgsManager& args, const std::string& command, const bool must_exist, fs::path& path, bilingual_str& error)
{
    const std::string labels_filename{args.GetArg("-labelsfile", "")};
    if (labels_filename.empty()) {
        error = strprintf(_("No labels file provided. To use %s, -labelsfile=<filename> must be provided."), command);
        return false;
    }

    path = fs::absolute(fs::PathFromString(labels_filename));
    if (must_exist && !fs::exists(path)) {
        error = strprintf(_("Labels file %s does not exist."), fs::PathToString(path));
        return false;
    }
    if (!must_exist && fs::exists(path)) {
        error = strprintf(_("File %s already exists. If you are sure this is what you want, move it out of the way first."), fs::PathToString(path));
        return false;
    }
    return true;
}

static std::optional<COutPoint> DecodeBIP329Output(std::string_view ref)
{
    const size_t separator{ref.find(':')};
    if (separator == std::string_view::npos || ref.find(':', separator + 1) != std::string_view::npos) return std::nullopt;
    auto txid{Txid::FromHex(ref.substr(0, separator))};
    if (!txid) return std::nullopt;
    const auto index{ToIntegral<uint32_t>(ref.substr(separator + 1))};
    if (!index || *index == std::numeric_limits<uint32_t>::max()) return std::nullopt;
    return COutPoint{*txid, *index};
}

static void WriteBIP329Record(std::ofstream& labels_file, UniValue&& record, size_t& exported)
{
    labels_file << record.write() << "\n";
    ++exported;
}

static std::optional<std::string> GetBIP329Keypath(const CWallet& wallet, const CTxDestination& dest)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    const CScript script{GetScriptForDestination(dest)};
    for (const auto spk_man : wallet.GetScriptPubKeyMans(script)) {
        if (const std::unique_ptr<CKeyMetadata> meta{spk_man->GetMetadata(dest)}) {
            if (!meta->has_key_origin || meta->key_origin.path.empty()) continue;
            const auto& path{meta->key_origin.path};
            const auto first{path.size() > 2 ? path.end() - 2 : path.begin()};
            const std::vector<uint32_t> keypath{first, path.end()};
            return FormatHDKeypath(keypath, /*apostrophe=*/true);
        }
    }
    return std::nullopt;
}

static std::optional<std::string> GetBIP329Origin(const CWallet& wallet, const CScript& script)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    CTxDestination dest;
    if (!ExtractDestination(script, dest)) return std::nullopt;

    for (const auto spk_man : wallet.GetScriptPubKeyMans(script)) {
        const auto desc_spk_man{dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man)};
        if (!desc_spk_man) continue;

        std::string desc_str;
        if (!desc_spk_man->GetDescriptorString(desc_str, /*priv=*/false)) continue;
        const auto paren_pos{desc_str.find('(')};
        if (paren_pos == std::string::npos) continue;

        const std::unique_ptr<CKeyMetadata> meta{spk_man->GetMetadata(dest)};
        if (!meta || !meta->has_key_origin) continue;

        std::vector<uint32_t> account_path{meta->key_origin.path};
        if (account_path.size() >= 2) account_path.resize(account_path.size() - 2);
        return strprintf("%s([%s%s])",
            desc_str.substr(0, paren_pos),
            HexStr(meta->key_origin.fingerprint),
            FormatHDKeypath(account_path, /*apostrophe=*/true));
    }
    return std::nullopt;
}

static std::optional<std::string> GetBIP329Origin(const CWallet& wallet, const CWalletTx& wtx)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    for (const CTxOut& txout : wtx.tx->vout) {
        if (!wallet.IsMine(txout)) continue;
        if (auto origin{GetBIP329Origin(wallet, txout.scriptPubKey)}) return origin;
    }
    return std::nullopt;
}

static void AddBIP329ConfirmationFields(const CWallet& wallet, const CWalletTx& wtx, UniValue& record)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    const auto* conf{wtx.state<TxStateConfirmed>()};
    if (!conf) return;

    if (conf->confirmed_block_height >= 0) record.pushKV("height", conf->confirmed_block_height);
    record.pushKV("time", FormatISO8601DateTime(wtx.GetTxTime()));
    record.pushKV("blockhash", conf->confirmed_block_hash.GetHex());
}

static void AddBIP329OutputContext(const CWallet& wallet, const CWalletTx& wtx,
                                   const COutputEntry& output, UniValue& record)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    if (IsValidDestination(output.destination)) {
        record.pushKV("address", EncodeDestination(output.destination));
        if (auto keypath{GetBIP329Keypath(wallet, output.destination)}) {
            record.pushKV("keypath", *keypath);
        }
    }

    record.pushKV("value", output.amount);
    AddBIP329ConfirmationFields(wallet, wtx, record);
}

static CAmount GetWalletCredit(const CWallet& wallet, const CWalletTx& wtx)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    CAmount credit{0};
    for (const CTxOut& txout : wtx.tx->vout) {
        if (wallet.IsMine(txout)) credit += txout.nValue;
    }
    return credit;
}

static void ExportTransactionRecords(CWallet& wallet, std::ofstream& labels_file, size_t& exported)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    for (const auto& ordered_tx : wallet.wtxOrdered) {
        const CWalletTx& wtx{*ordered_tx.second};
        CAmount fee{0};
        std::list<COutputEntry> list_received;
        std::list<COutputEntry> list_sent;
        CachedTxGetAmounts(wallet, wtx, list_received, list_sent, fee, /*include_change=*/false);

        const CAmount debit{CachedTxGetDebit(wallet, wtx, /*avoid_reuse=*/false)};
        const CAmount credit{GetWalletCredit(wallet, wtx)};
        UniValue tx_record{UniValue::VOBJ};
        tx_record.pushKV("type", "tx");
        tx_record.pushKV("ref", wtx.GetHash().GetHex());
        if (const auto comment{wtx.mapValue.find("comment")};
            comment != wtx.mapValue.end() && !comment->second.empty()) {
            tx_record.pushKV("label", comment->second);
        }
        if (fee > 0) tx_record.pushKV("fee", fee);
        tx_record.pushKV("value", credit - debit);
        if (auto origin{GetBIP329Origin(wallet, wtx)}) tx_record.pushKV("origin", *origin);
        AddBIP329ConfirmationFields(wallet, wtx, tx_record);
        WriteBIP329Record(labels_file, std::move(tx_record), exported);

        for (const COutputEntry& sent : list_sent) {
            UniValue record{UniValue::VOBJ};
            record.pushKV("type", "output");
            record.pushKV("ref", strprintf("%s:%u", wtx.GetHash().GetHex(), sent.vout));
            const auto* address_book_entry{wallet.FindAddressBookEntry(sent.destination)};
            if (address_book_entry) record.pushKV("label", address_book_entry->GetLabel());
            record.pushKV("category", "send");
            record.pushKV("wallet_value", -sent.amount);
            if (fee > 0) record.pushKV("fee", fee);
            AddBIP329OutputContext(wallet, wtx, sent, record);
            WriteBIP329Record(labels_file, std::move(record), exported);
        }

        for (const COutputEntry& received : list_received) {
            UniValue record{UniValue::VOBJ};
            record.pushKV("type", "output");
            record.pushKV("ref", strprintf("%s:%u", wtx.GetHash().GetHex(), received.vout));
            const auto* address_book_entry{wallet.FindAddressBookEntry(received.destination)};
            if (address_book_entry) record.pushKV("label", address_book_entry->GetLabel());
            if (wtx.IsCoinBase()) {
                record.pushKV("category", "generate");
            } else {
                record.pushKV("category", "receive");
            }
            record.pushKV("wallet_value", received.amount);
            AddBIP329OutputContext(wallet, wtx, received, record);
            WriteBIP329Record(labels_file, std::move(record), exported);
        }
    }
}

static void ExportDescriptorRecords(CWallet& wallet, std::ofstream& labels_file, size_t& exported)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    std::set<std::string> descriptors;
    for (const auto spk_man : wallet.GetAllScriptPubKeyMans()) {
        const auto desc_spk_man{dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man)};
        if (!desc_spk_man) continue;
        std::string desc_str;
        if (desc_spk_man->GetDescriptorString(desc_str, /*priv=*/false)) descriptors.insert(desc_str);
    }

    for (const std::string& desc_str : descriptors) {
        UniValue record{UniValue::VOBJ};
        record.pushKV("type", "descriptor");
        record.pushKV("ref", desc_str);
        record.pushKV("label", "descriptor");
        WriteBIP329Record(labels_file, std::move(record), exported);
    }
}

static bool ExportLabels(const ArgsManager& args, CWallet& wallet, bilingual_str& error)
{
    fs::path path;
    if (!GetLabelsPath(args, "exportlabels", /*must_exist=*/false, path, error)) return false;

    std::ofstream labels_file{path.std_path()};
    if (labels_file.fail()) {
        error = strprintf(_("Unable to open %s for writing"), fs::PathToString(path));
        return false;
    }

    size_t exported{0};
    {
        LOCK(wallet.cs_wallet);
        wallet.ForEachAddrBookEntry([&](const CTxDestination& dest, const std::string& label,
                                        bool is_change, const std::optional<AddressPurpose>& purpose) {
            if (is_change) return;
            UniValue record{UniValue::VOBJ};
            record.pushKV("type", "addr");
            record.pushKV("ref", EncodeDestination(dest));
            record.pushKV("label", label);
            WriteBIP329Record(labels_file, std::move(record), exported);
        });

        std::vector<COutPoint> locked_coins;
        wallet.ListLockedCoins(locked_coins);
        for (const COutPoint& coin : locked_coins) {
            UniValue record{UniValue::VOBJ};
            record.pushKV("type", "output");
            record.pushKV("ref", strprintf("%s:%u", coin.hash.GetHex(), coin.n));
            record.pushKV("spendable", false);
            WriteBIP329Record(labels_file, std::move(record), exported);
        }

        ExportTransactionRecords(wallet, labels_file, exported);
        ExportDescriptorRecords(wallet, labels_file, exported);
    }

    if (labels_file.fail()) {
        error = strprintf(_("Unable to write to %s"), fs::PathToString(path));
        return false;
    }

    tfm::format(std::cout, "Exported %u BIP329 records to %s\n", exported, fs::PathToString(path));
    return true;
}

static bool ImportLabels(const ArgsManager& args, CWallet& wallet, bilingual_str& error)
{
    fs::path path;
    if (!GetLabelsPath(args, "importlabels", /*must_exist=*/true, path, error)) return false;

    std::ifstream labels_file{path.std_path()};
    if (labels_file.fail()) {
        error = strprintf(_("Unable to open %s for reading"), fs::PathToString(path));
        return false;
    }

    size_t imported{0};
    size_t ignored{0};
    size_t line_number{0};
    std::string line;
    while (std::getline(labels_file, line)) {
        ++line_number;
        UniValue record;
        if (!record.read(line) || !record.isObject()) {
            error = strprintf(_("Error: Unable to parse BIP329 record on line %u as a JSON object"), line_number);
            return false;
        }

        const UniValue& type_value{record.find_value("type")};
        const UniValue& ref_value{record.find_value("ref")};
        if (!type_value.isStr() || !ref_value.isStr()) {
            error = strprintf(_("Error: BIP329 record on line %u must contain string \"type\" and \"ref\" fields"), line_number);
            return false;
        }

        const std::string& type{type_value.get_str()};
        const std::string& ref{ref_value.get_str()};
        if (type == "addr") {
            const UniValue& label_value{record.find_value("label")};
            if (label_value.isNull()) {
                ++ignored;
                continue;
            }
            if (!label_value.isStr()) {
                error = strprintf(_("Error: BIP329 address record on line %u must contain a string \"label\" field"), line_number);
                return false;
            }
            if (!IsValidDestinationString(ref)) {
                error = strprintf(_("Error: BIP329 address record on line %u has an invalid address for the selected chain: %s"), line_number, ref);
                return false;
            }

            const CTxDestination dest{DecodeDestination(ref)};
            const AddressPurpose purpose{[&] {
                LOCK(wallet.cs_wallet);
                return wallet.IsMine(dest) ? AddressPurpose::RECEIVE : AddressPurpose::SEND;
            }()};
            if (!wallet.SetAddressBook(dest, label_value.get_str(), purpose)) {
                error = strprintf(_("Error: Unable to write BIP329 address label on line %u"), line_number);
                return false;
            }
            ++imported;
        } else if (type == "output") {
            const UniValue& spendable_value{record.find_value("spendable")};
            if (spendable_value.isNull()) {
                ++ignored;
                continue;
            }
            if (!spendable_value.isBool()) {
                error = strprintf(_("Error: BIP329 output record on line %u must contain a boolean \"spendable\" field"), line_number);
                return false;
            }

            auto outpoint{DecodeBIP329Output(ref)};
            if (!outpoint) {
                error = strprintf(_("Error: BIP329 output record on line %u has an invalid output reference: %s"), line_number, ref);
                return false;
            }

            LOCK(wallet.cs_wallet);
            if (spendable_value.get_bool()) {
                if (!wallet.UnlockCoin(*outpoint)) {
                    error = strprintf(_("Error: Unable to unlock BIP329 output on line %u"), line_number);
                    return false;
                }
            } else if (!wallet.LockCoin(*outpoint, /*persist=*/true)) {
                error = strprintf(_("Error: Unable to lock BIP329 output on line %u"), line_number);
                return false;
            }
            ++imported;
        } else {
            ++ignored;
        }
    }

    if (labels_file.bad()) {
        error = strprintf(_("Unable to read from %s"), fs::PathToString(path));
        return false;
    }

    tfm::format(std::cout, "Imported %u BIP329 records from %s; ignored %u unsupported records\n", imported, fs::PathToString(path), ignored);
    return true;
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
    } else if (command == "exportlabels" || command == "importlabels") {
        DatabaseOptions options;
        ReadDatabaseArgs(args, options);
        options.require_existing = true;
        const std::shared_ptr<CWallet> wallet_instance = MakeWallet(name, path, options);
        if (!wallet_instance) return false;

        bilingual_str error;
        const bool ret{command == "exportlabels" ? ExportLabels(args, *wallet_instance, error) : ImportLabels(args, *wallet_instance, error)};
        wallet_instance->Close();
        if (!ret && !error.empty()) {
            tfm::format(std::cerr, "%s\n", error.original);
        }
        return ret;
    } else {
        tfm::format(std::cerr, "Invalid command: %s\n", command);
        return false;
    }

    return true;
}
} // namespace WalletTool
} // namespace wallet

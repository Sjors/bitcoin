// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/mining_args.h>

#include <common/args.h>
#include <common/messages.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <tinyformat.h>
#include <util/moneystr.h>
#include <util/translation.h>

#include <optional>
#include <string>

using common::AmountErrMsg;

namespace node {

util::Result<void> CheckBlockMaxWeight(size_t block_max_weight, const std::string& arg_name)
{
    if (block_max_weight > MAX_BLOCK_WEIGHT) {
        return util::Error{Untranslated(strprintf("%s (%zu) exceeds consensus maximum block weight (%u)",
                                                  arg_name.empty() ? "block_max_weight" : arg_name,
                                                  block_max_weight, MAX_BLOCK_WEIGHT))};
    }
    return {};
}

util::Result<void> CheckBlockReservedWeight(size_t block_reserved_weight, const std::string& arg_name)
{
    if (block_reserved_weight < MINIMUM_BLOCK_RESERVED_WEIGHT) {
        return util::Error{Untranslated(strprintf("%s (%zu) is lower than minimum safety value of (%u)",
                                                  arg_name.empty() ? "block_reserved_weight" : arg_name,
                                                  block_reserved_weight, MINIMUM_BLOCK_RESERVED_WEIGHT))};
    }
    if (block_reserved_weight > MAX_BLOCK_WEIGHT) {
        return util::Error{Untranslated(strprintf("%s (%zu) exceeds consensus maximum block weight (%u)",
                                                  arg_name.empty() ? "block_reserved_weight" : arg_name,
                                                  block_reserved_weight, MAX_BLOCK_WEIGHT))};
    }
    return {};
}

util::Result<void> CheckCoinbaseOutputMaxAdditionalSigops(size_t sigops, const std::string& arg_name)
{
    if (sigops > MAX_BLOCK_SIGOPS_COST) {
        return util::Error{Untranslated(strprintf("%s (%zu) exceeds consensus maximum block sigops cost (%d)",
                                                  arg_name.empty() ? "coinbase_output_max_additional_sigops" : arg_name,
                                                  sigops, MAX_BLOCK_SIGOPS_COST))};
    }
    return {};
}

util::Result<void> ReadMiningArgs(const ArgsManager& args, MiningArgs& mining_args)
{
    if (const auto arg{args.GetArg("-blockmintxfee")}) {
        std::optional<CAmount> block_min_tx_fee{ParseMoney(*arg)};
        if (!block_min_tx_fee) return util::Error{AmountErrMsg("blockmintxfee", *arg)};
        mining_args.block_min_fee_rate = CFeeRate{*block_min_tx_fee};
    }

    const size_t max_block_weight = args.GetIntArg("-blockmaxweight", DEFAULT_BLOCK_MAX_WEIGHT);
    if (auto result{CheckBlockMaxWeight(max_block_weight, "-blockmaxweight")}; !result) {
        return result;
    }
    mining_args.default_block_max_weight = max_block_weight;

    const size_t block_reserved_weight = args.GetIntArg("-blockreservedweight", DEFAULT_BLOCK_RESERVED_WEIGHT);
    if (auto result{CheckBlockReservedWeight(block_reserved_weight, "-blockreservedweight")}; !result) {
        return result;
    }
    mining_args.default_block_reserved_weight = block_reserved_weight;

    mining_args.print_modified_fee = args.GetBoolArg("-printpriority", mining_args.print_modified_fee);

    return {};
}

} // namespace node

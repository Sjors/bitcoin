// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/descriptor_info.h>

#include <univalue.h>

namespace wallet {

UniValue DescriptorInfoToUniValue(const WalletDescriptorInfo& info)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("desc", info.descriptor);
    obj.pushKV("timestamp", info.creation_time);
    obj.pushKV("active", info.active);
    if (info.internal.has_value()) {
        obj.pushKV("internal", info.internal.value());
    }
    if (info.range.has_value()) {
        UniValue range(UniValue::VARR);
        range.push_back(info.range->first);
        // range_end is exclusive internally, display as inclusive (hence -1)
        range.push_back(info.range->second - 1);
        obj.pushKV("range", std::move(range));
        obj.pushKV("next", info.next_index);
        obj.pushKV("next_index", info.next_index);
    }
    return obj;
}

} // namespace wallet

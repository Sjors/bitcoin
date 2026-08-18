// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_DESCRIPTOR_INFO_H
#define BITCOIN_WALLET_DESCRIPTOR_INFO_H

#include <wallet/export.h>

class UniValue;

namespace wallet {

/**
 * Information about a wallet descriptor, used for serialization to JSON.
 * This struct captures all the metadata needed for listdescriptors output
 * and importdescriptors input.
 */
using WalletDescriptorInfo = WalletDescInfo;

/**
 * Convert a WalletDescriptorInfo to a UniValue object.
 * The output format is compatible with both listdescriptors output and
 * importdescriptors input.
 */
UniValue DescriptorInfoToUniValue(const WalletDescriptorInfo& info);

} // namespace wallet

#endif // BITCOIN_WALLET_DESCRIPTOR_INFO_H

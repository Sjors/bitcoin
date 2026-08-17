// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_DESCRIPTOR_RECOMBINER_H
#define BITCOIN_WALLET_DESCRIPTOR_RECOMBINER_H

#include <wallet/export.h>

#include <map>
#include <optional>
#include <span>
#include <string>

namespace wallet {

struct RecombinedDescriptor {
    std::string descriptor;
    bool internal;
};

/**
 * Recombine two descriptor branches into a BIP389 multipath descriptor.
 *
 * The returned descriptor has no checksum. It is only returned if parsing it
 * produces exactly the two input descriptors in receive/change order.
 */
std::optional<std::string> RecombineDescriptorPair(const std::string& receive, const std::string& change);

/**
 * Find unique receive/change pairs and recombine them into BIP389 descriptors.
 *
 * The result maps each original descriptor to its combined descriptor and its
 * position in that descriptor. Unpaired and ambiguously paired descriptors are
 * omitted.
 */
std::map<std::string, RecombinedDescriptor> RecombineDescriptors(std::span<const WalletDescInfo> descriptors);

} // namespace wallet

#endif // BITCOIN_WALLET_DESCRIPTOR_RECOMBINER_H

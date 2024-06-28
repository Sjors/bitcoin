// Copyright (c) 2013-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hash.h>
#include <span.h>
#include <crypto/common.h>

#include <bit>
#include <string>

uint256 SHA256Uint256(const uint256& input)
{
    uint256 result;
    CSHA256().Write(input.begin(), 32).Finalize(result.begin());
    return result;
}

HashWriter TaggedHash(const std::string& tag)
{
    HashWriter writer{};
    uint256 taghash;
    CSHA256().Write((const unsigned char*)tag.data(), tag.size()).Finalize(taghash.begin());
    writer << taghash << taghash;
    return writer;
}

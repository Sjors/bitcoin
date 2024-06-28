// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Hash functions that are not consensus.

#ifndef BITCOIN_UTIL_HASH_H
#define BITCOIN_UTIL_HASH_H

#include <span.h>
#include <uint256.h>

typedef uint256 ChainCode;

unsigned int MurmurHash3(unsigned int nHashSeed, Span<const unsigned char> vDataToHash);

void BIP32Hash(const ChainCode &chainCode, unsigned int nChild, unsigned char header, const unsigned char data[32], unsigned char output[64]);

#endif // BITCOIN_UTIL_HASH_H

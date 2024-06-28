// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_EXTPUBKEY_H
#define BITCOIN_UTIL_EXTPUBKEY_H

#include <uint256.h>

const unsigned int BIP32_EXTKEY_SIZE = 74;
const unsigned int BIP32_EXTKEY_WITH_VERSION_SIZE = 78;

typedef uint256 ChainCode;

struct CExtPubKey {
    unsigned char version[4];
    unsigned char nDepth;
    unsigned char vchFingerprint[4];
    unsigned int nChild;
    ChainCode chaincode;
    CPubKey pubkey;

    friend bool operator==(const CExtPubKey &a, const CExtPubKey &b)
    {
        return a.nDepth == b.nDepth &&
            memcmp(a.vchFingerprint, b.vchFingerprint, sizeof(vchFingerprint)) == 0 &&
            a.nChild == b.nChild &&
            a.chaincode == b.chaincode &&
            a.pubkey == b.pubkey;
    }

    friend bool operator!=(const CExtPubKey &a, const CExtPubKey &b)
    {
        return !(a == b);
    }

    friend bool operator<(const CExtPubKey &a, const CExtPubKey &b)
    {
        if (a.pubkey < b.pubkey) {
            return true;
        } else if (a.pubkey > b.pubkey) {
            return false;
        }
        return a.chaincode < b.chaincode;
    }

    void Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const;
    void Decode(const unsigned char code[BIP32_EXTKEY_SIZE]);
    void EncodeWithVersion(unsigned char code[BIP32_EXTKEY_WITH_VERSION_SIZE]) const;
    void DecodeWithVersion(const unsigned char code[BIP32_EXTKEY_WITH_VERSION_SIZE]);
    [[nodiscard]] bool Derive(CExtPubKey& out, unsigned int nChild) const;
};

#endif // BITCOIN_UTIL_EXTPUBKEY_H

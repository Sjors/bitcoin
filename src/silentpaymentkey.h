// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SILENTPAYMENTKEY_H
#define BITCOIN_SILENTPAYMENTKEY_H

#include <key.h>
#include <pubkey.h>

#include <cstring>

const unsigned int BIP352_SPKEY_SIZE = 74;

struct SpPubKey {
    unsigned char version[1];
    unsigned char vchFingerprint[4];
    int maximumNumberOfLabels;
    CKey scanKey;
    CPubKey spendKey;

    SpPubKey() = default;

    SpPubKey(CKey scan_key, CPubKey spend_key) : scanKey(scan_key), spendKey(spend_key)
    {
      memset(version, 0, sizeof(version));
      memset(vchFingerprint, 0, sizeof(vchFingerprint));
      maximumNumberOfLabels = 0;
    }

    friend bool operator==(const SpPubKey &a, const SpPubKey &b)
    {
      return memcmp(a.version, b.version, sizeof(version)) == 0 &&
          memcmp(a.vchFingerprint, b.vchFingerprint, sizeof(vchFingerprint)) == 0 &&
          a.maximumNumberOfLabels == b.maximumNumberOfLabels &&
          a.scanKey == b.scanKey &&
          a.spendKey == b.spendKey;
    }

    friend bool operator!=(const SpPubKey &a, const SpPubKey &b)
    {
      return !(a == b);
    }

    friend bool operator<(const SpPubKey &a, const SpPubKey &b)
    {
      CPubKey aScanPubKey = a.scanKey.GetPubKey();
      CPubKey bScanPubKey = b.scanKey.GetPubKey();
      if (aScanPubKey < bScanPubKey) {
          return true;
      } else if (aScanPubKey > bScanPubKey) {
          return false;
      }
      return a.spendKey < b.spendKey;
    }

    bool IsValid()
    {
      return scanKey.IsValid() && spendKey.IsValid();
    }

    void Encode(unsigned char code[BIP352_SPKEY_SIZE]) const;
    void Decode(const unsigned char code[BIP352_SPKEY_SIZE]);

    //! Get the KeyID of this Silent Payment public key (hash of its serialization)
    CKeyID GetID() const;
};

struct SpKey {
    unsigned char version[1];
    unsigned char vchFingerprint[4];
    int maximumNumberOfLabels;
    CKey scanKey;
    CKey spendKey;

    friend bool operator==(const SpKey& a, const SpKey& b)
    {
      return memcmp(a.version, b.version, sizeof(version)) == 0 &&
          memcmp(a.vchFingerprint, b.vchFingerprint, sizeof(vchFingerprint)) == 0 &&
          a.maximumNumberOfLabels == b.maximumNumberOfLabels &&
          a.scanKey == b.scanKey &&
          a.spendKey == b.spendKey;
    }

    SpKey() = default;
    SpKey(const SpPubKey& sppub, const CKey& scanKey_in, const CKey& spendKey_in) : maximumNumberOfLabels(sppub.maximumNumberOfLabels), scanKey(scanKey_in), spendKey(spendKey_in)
    {
      std::copy(sppub.version, sppub.version + sizeof(sppub.version), version);
      std::copy(sppub.vchFingerprint, sppub.vchFingerprint + sizeof(sppub.vchFingerprint), vchFingerprint);
    }

    bool IsValid()
    {
      return scanKey.IsValid() && spendKey.IsValid();
    }

    void Encode(unsigned char code[BIP352_SPKEY_SIZE]) const;
    void Decode(const unsigned char code[BIP352_SPKEY_SIZE]);
    SpPubKey Neuter();
};

#endif // BITCOIN_SILENTPAYMENTKEY_H
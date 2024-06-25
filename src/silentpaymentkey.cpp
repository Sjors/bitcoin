// Copyright (c) 2018-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hash.h>
#include <silentpaymentkey.h>
#include <span.h>

void SpPubKey::Encode(unsigned char code[BIP352_SPKEY_SIZE]) const
{
  // Should probably check that keys are compressed here
  memcpy(code, version, 1);
  memcpy(code+1, vchFingerprint, 4);
  WriteBE32(code+5, maximumNumberOfLabels);
  memcpy(code+9, scanKey.begin(), 32);
  memcpy(code+41, spendKey.begin(), 33);
}

void SpPubKey::Decode(const unsigned char code[BIP352_SPKEY_SIZE])
{
  memcpy(version, code, 1);
  memcpy(vchFingerprint, code+1, 4);
  maximumNumberOfLabels = ReadBE32(code+5);
  scanKey.Set(code+9, code+41, true);
  spendKey.Set(code+41, code+BIP352_SPKEY_SIZE);
}

CKeyID SpPubKey::GetID() const
{
  unsigned char code[BIP352_SPKEY_SIZE];
  Encode(code);
  return CKeyID(Hash160(Span(code, BIP352_SPKEY_SIZE)));
}

void SpKey::Encode(unsigned char code[BIP352_SPKEY_SIZE]) const
{
  // Should probably check that keys are compressed here
  memcpy(code, version, 1);
  memcpy(code+1, vchFingerprint, 4);
  WriteBE32(code+5, maximumNumberOfLabels);
  memcpy(code+9, scanKey.begin(), 32);
  code[41] = 0x00;
  memcpy(code+42, spendKey.begin(), 32);
}

void SpKey::Decode(const unsigned char code[BIP352_SPKEY_SIZE])
{
  if (code[41] != 0x00) {
    // return early leave SpKey invalid
    return;
  }
  memcpy(version, code, 1);
  memcpy(vchFingerprint, code+1, 4);
  maximumNumberOfLabels = ReadBE32(code+5);
  scanKey.Set(code+9, code+41, true);
  spendKey.Set(code+42, code+BIP352_SPKEY_SIZE, true);
}

SpPubKey SpKey::Neuter()
{
  SpPubKey ret;
  memcpy(ret.version, version, 1);
  memcpy(ret.vchFingerprint, vchFingerprint, 4);
  ret.maximumNumberOfLabels = maximumNumberOfLabels;
  ret.scanKey = scanKey;
  ret.spendKey = spendKey.GetPubKey();
  return ret;
}

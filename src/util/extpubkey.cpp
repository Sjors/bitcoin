// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pubkey.h>
#include <util/extpubkey.h>
#include <util/hash.h>

#include <secp256k1.h>
#include <cassert>

namespace {

struct Secp256k1SelfTester
{
    Secp256k1SelfTester() {
        /* Run libsecp256k1 self-test before using the secp256k1_context_static. */
        secp256k1_selftest();
    }
} SECP256K1_SELFTESTER;

} // namespace

void CExtPubKey::Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const {
    code[0] = nDepth;
    memcpy(code+1, vchFingerprint, 4);
    WriteBE32(code+5, nChild);
    memcpy(code+9, chaincode.begin(), 32);
    assert(pubkey.size() == CPubKey::COMPRESSED_SIZE);
    memcpy(code+41, pubkey.begin(), CPubKey::COMPRESSED_SIZE);
}

void CExtPubKey::Decode(const unsigned char code[BIP32_EXTKEY_SIZE]) {
    nDepth = code[0];
    memcpy(vchFingerprint, code+1, 4);
    nChild = ReadBE32(code+5);
    memcpy(chaincode.begin(), code+9, 32);
    pubkey.Set(code+41, code+BIP32_EXTKEY_SIZE);
    if ((nDepth == 0 && (nChild != 0 || ReadLE32(vchFingerprint) != 0)) || !pubkey.IsFullyValid()) pubkey = CPubKey();
}

void CExtPubKey::EncodeWithVersion(unsigned char code[BIP32_EXTKEY_WITH_VERSION_SIZE]) const
{
    memcpy(code, version, 4);
    Encode(&code[4]);
}

void CExtPubKey::DecodeWithVersion(const unsigned char code[BIP32_EXTKEY_WITH_VERSION_SIZE])
{
    memcpy(version, code, 4);
    Decode(&code[4]);
}

bool CExtPubKey::Derive(CExtPubKey &out, unsigned int _nChild) const {
    if (nDepth == std::numeric_limits<unsigned char>::max()) return false;
    out.nDepth = nDepth + 1;
    CKeyID id = pubkey.GetID();
    memcpy(out.vchFingerprint, &id, 4);
    out.nChild = _nChild;

    CPubKey& pubkeyChild = out.pubkey;
    ChainCode& ccChild = out.chaincode;

    assert(pubkey.IsValid());
    assert((_nChild >> 31) == 0);
    assert(pubkey.size() == CPubKey::COMPRESSED_SIZE);
    unsigned char child_extkey_bytes[64];
    // Derive child chaincode, the result fills all of child_extkey_bytes.
    // We copy the last 32 bytes into ccChild, while the first 32 bytes
    // are used to tweak the public key for child derivation.
    BIP32Hash(chaincode, _nChild, *pubkey.begin(), pubkey.begin()+1, child_extkey_bytes);
    memcpy(ccChild.begin(), child_extkey_bytes+32, 32);
    secp256k1_pubkey child_pubkey;
    // Copy parent pubkey bytes into a secp256k1_pubkey
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_static, &child_pubkey, pubkey.vch, pubkey.size())) {
        return false;
    }
    // Tweak to derive the child pubkey using the first 32 bytes of child_extkey_bytes
    if (!secp256k1_ec_pubkey_tweak_add(secp256k1_context_static, &child_pubkey, child_extkey_bytes)) {
        return false;
    }
    // Serialize child_pubkey into pub
    unsigned char pub[CPubKey::COMPRESSED_SIZE];
    size_t publen = CPubKey::COMPRESSED_SIZE;
    secp256k1_ec_pubkey_serialize(secp256k1_context_static, pub, &publen, &child_pubkey, SECP256K1_EC_COMPRESSED);
    pubkeyChild.Set(pub, pub + publen);
    return true;
}

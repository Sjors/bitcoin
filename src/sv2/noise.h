// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SV2_NOISE_H
#define BITCOIN_SV2_NOISE_H

#include <compat/compat.h>
#include <crypto/poly1305.h>
#include <key.h>
#include <pubkey.h>
#include <random.h>
#include <streams.h>
#include <uint256.h>

/** The Noise Protocol Framework
 *  https://noiseprotocol.org/noise.html
 *  Revision 38, 2018-07-11
 *
 *  Stratum v2 handshake and cipher specification:
 *  https://github.com/stratum-mining/sv2-spec/blob/main/04-Protocol-Security.md
 */

/** Section 3: All Noise messages are less than or equal to 65535 bytes in length. */
static constexpr size_t NOISE_MAX_CHUNK_SIZE = 65535;

static constexpr size_t HASHLEN{32};
using NoiseHash = std::array<uint8_t, HASHLEN>;

/** Simple certificate for the static key signed by the authority key.
 * See 4.5.2 and 4.5.3 of the Stratum v2 spec.
 */
class Sv2SignatureNoiseMessage
{
public:
    /** Size of a Schnorr signature. */
    static constexpr size_t SCHNORR_SIGNATURE_SIZE = 64;
    /** Size of serialized message, which does not include the static key.  */
    static constexpr size_t SIZE = 2 + 4 + 4 + SCHNORR_SIGNATURE_SIZE;

private:
    uint16_t m_version = 0;
    uint32_t m_valid_from = 0;
    uint32_t m_valid_to = 0;
    std::array<unsigned char, SCHNORR_SIGNATURE_SIZE> m_sig;

    /** Hash of version, valid from/to and the static key. */
    uint256 GetHash();
    void SignSchnorr(const CKey& authority_key, std::span<unsigned char> sig);

public:
    Sv2SignatureNoiseMessage() = default;
    Sv2SignatureNoiseMessage(uint16_t version, uint32_t valid_from, uint32_t valid_to, const XOnlyPubKey& static_key, const CKey& authority_key);

    /* The certificate serializes pubkeys in x-only format, not EllSwift. */
    XOnlyPubKey m_static_key = {};

    [[nodiscard]] bool Validate(XOnlyPubKey authority_key);

    template <typename Stream>
    // The static_key is signed for, but not serialized.
    void Serialize(Stream& s) const
    {
        s << m_version
          << m_valid_from
          << m_valid_to
          << m_sig;
    }
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        s >> m_version
          >> m_valid_from
          >> m_valid_to
          >> m_sig;
    }
};

/*
 * The CipherState uses m_key (k) and m_nonce (n) to encrypt and decrypt ciphertexts.
 * During the handshake phase each party has a single CipherState, but during
 * the transport phase each party has two CipherState objects: one for sending,
 * and one for receiving.
 *
 * See chapter "5. Processing rules" of the Noise paper.
 */
class Sv2CipherState
{
public:
    Sv2CipherState() = default;
    explicit Sv2CipherState(NoiseHash&& key);

    /** Decrypt message
     * @param[in] associated_data associated data
     * @param[in] ciphertext message with encrypted and authenticated chunks.
     * @param[out] plain message (defragmented)
     * @returns whether decryption succeeded
     */
    [[nodiscard]] bool DecryptWithAd(std::span<const std::byte> associated_data, std::span<std::byte> ciphertext, std::span<std::byte> plain);

    /** Encrypt message
     * @param[in] associated_data associated data
     * @param[in] plain message
     * @param[out] ciphertext message with encrypted and authenticated chunks.
     * @returns whether encryption succeeded
     */
    [[nodiscard]] bool EncryptWithAd(std::span<const std::byte> associated_data, std::span<const std::byte> plain, std::span<std::byte> ciphertext);

    /** The message will be chunked in NOISE_MAX_CHUNK_SIZE parts and expanded
     *  by 16 bytes per chunk for its MAC.
     *
     * @param[in] plain message. Can't point to the same memory location as ciphertext,
     *                  because each encrypted message chunk would override the
     *                  start of the next plain text chunk.
     * @param[out] ciphertext   message with encrypted and authenticated chunks
     * @return whether encryption succeeded. Only fails if nonce is uint64_max.
     */
    [[nodiscard]] bool EncryptMessage(std::span<const std::byte> plain, std::span<std::byte> ciphertext);

    /** Decrypt message.
     *
     * @param[in] ciphertext encrypted message
     * @param[out] plain decrypted message. May point to the same memory location
     *                  as ciphertext. The result is defragmented.
     */
    [[nodiscard]] bool DecryptMessage(std::span<std::byte> ciphertext, std::span<std::byte> plain);

private:
    NoiseHash m_key{0};
    uint64_t m_nonce = 0;
};

/*
 * A SymmetricState object contains a CipherState plus m_chaining_key (ck) and
 * m_hash_output (h) variables. It is so-named because it encapsulates all the
 * "symmetric crypto" used by Noise. During the handshake phase each party has
 * a single SymmetricState, which can be deleted once the handshake is finished.
 *
 * See chapter "5. Processing rules" of the Noise paper.
 */
class Sv2SymmetricState
{
public:
    // Sha256 hash of the ascii encoding - "Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256".
    // This is the first step required when setting up the chaining key.
    static constexpr NoiseHash PROTOCOL_NAME_HASH = {
        46, 180, 120, 129, 32, 142, 158, 238, 31, 102, 159, 103, 198, 110, 231, 14,
        169, 234, 136, 9, 13, 80, 63, 232, 48, 220, 75, 200, 62, 41, 191, 16};

    // The double hash of protocol name "Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256".
    static constexpr NoiseHash PROTOCOL_NAME_DOUBLE_HASH = {
        146, 47, 163, 46, 79, 72, 124, 13, 89, 202, 163, 190, 215, 137, 156, 227,
        217, 141, 183, 225, 61, 189, 59, 124, 242, 210, 61, 212, 51, 220, 97, 4};

    Sv2SymmetricState() : m_chaining_key{PROTOCOL_NAME_HASH} {}

    void MixHash(const std::span<const std::byte> input);
    void MixKey(const std::span<const std::byte> input_key_material);
    [[nodiscard]] bool EncryptAndHash(std::span<const std::byte> plain, std::span<std::byte> ciphertext);
    [[nodiscard]] bool DecryptAndHash(std::span<std::byte> ciphertext, std::span<std::byte> plain);
    std::array<Sv2CipherState, 2> Split();

    uint256 GetHashOutput();

    /* For testing */
    void LogChainingKey();
    std::string GetChainingKey();

private:
    NoiseHash m_chaining_key;
    uint256 m_hash_output{uint256(PROTOCOL_NAME_DOUBLE_HASH)};
    Sv2CipherState m_cipher_state;

    void HKDF2(const std::span<const std::byte> input_key_material,
               NoiseHash& out0,
               NoiseHash& out1);
};

/*
 * A HandshakeState object contains a SymmetricState plus DH variables (s, e, rs, re)
 * and a variable representing the handshake pattern. During the handshake phase
 * each party has a single HandshakeState, which can be deleted once the handshake
 * is finished.
 *
 * See chapter "5. Processing rules" of the Noise paper.
 */

class Sv2HandshakeState
{
public:
    static constexpr size_t ELLSWIFT_PUB_KEY_SIZE{64};
    static constexpr size_t ECDH_OUTPUT_SIZE{32};

    static constexpr size_t HANDSHAKE_STEP2_SIZE = ELLSWIFT_PUB_KEY_SIZE + ELLSWIFT_PUB_KEY_SIZE +
                                                   Poly1305::TAGLEN + Sv2SignatureNoiseMessage::SIZE + Poly1305::TAGLEN;

    /*
     * If we are the initiator m_authority_pubkey must be set in order to verify
     * the received certificate.
     */
    Sv2HandshakeState(CKey&& static_key,
                      XOnlyPubKey authority_pubkey) : m_static_key{static_key},
                                                        m_authority_pubkey{authority_pubkey}
    {
        m_static_ellswift_pk = static_key.EllSwiftCreate(MakeByteSpan(GetRandHash()));
    };

    /*
     * If we are the responder, the certificate must be set
     */
    Sv2HandshakeState(CKey&& static_key,
                      Sv2SignatureNoiseMessage&& certificate) : m_static_key{static_key},
                                                                m_certificate{certificate}
    {
        m_static_ellswift_pk = static_key.EllSwiftCreate(MakeByteSpan(GetRandHash()));
    };

    /** Handshake step 1 for initiator: -> e */
    void WriteMsgEphemeralPK(std::span<std::byte> msg);
    /** Handshake step 1 for responder: -> e */
    void ReadMsgEphemeralPK(std::span<std::byte> msg);
    /** During handshake step 2, put our ephmeral key, static key
     * and certificate in the buffer: <- e, ee, s, es, SIGNATURE_NOISE_MESSAGE
     */
    void WriteMsgES(std::span<std::byte> msg);
    /** During handshake step 2, read the remote ephmeral key, static key
     * and certificate. Verify their certificate.
     * <- e, ee, s, es, SIGNATURE_NOISE_MESSAGE
     */
    [[nodiscard]] bool ReadMsgES(std::span<std::byte> msg);

    std::array<Sv2CipherState, 2> SplitSymmetricState();
    uint256 GetHashOutput();

    void SetEphemeralKey(CKey&& key);

private:
    /** Our static key (s) */
    CKey m_static_key;
    /** EllSwift encoded static key, for optimized ECDH */
    EllSwiftPubKey m_static_ellswift_pk;
    /** Our ephemeral key (e) */
    CKey m_ephemeral_key;
    /** EllSwift encoded ephemeral key, for optimized ECDH */
    EllSwiftPubKey m_ephemeral_ellswift_pk;
    /** Remote static key (rs) */
    EllSwiftPubKey m_remote_static_ellswift_pk;
    /** Remote ephemeral key (re) */
    EllSwiftPubKey m_remote_ephemeral_ellswift_pk;
    Sv2SymmetricState m_symmetric_state;
    /** Certificate signed by m_authority_pubkey. */
    std::optional<Sv2SignatureNoiseMessage> m_certificate;
    /** Authority public key. */
    std::optional<XOnlyPubKey> m_authority_pubkey;

    /** Generate ephemeral key, sets set m_ephemeral_key and m_ephemeral_ellswift_pk */
    void GenerateEphemeralKey() noexcept;
};

/**
 * Interface somewhat similar to BIP324Cipher for use by a Transport class.
 * The initiator and responder roles have their own constructor.
 * FinishHandshake() must be called after all handshake bytes have been processed.
 */
class Sv2Cipher
{
public:
    Sv2Cipher(CKey&& static_key, XOnlyPubKey authority_pubkey);
    Sv2Cipher(CKey&& static_key, Sv2SignatureNoiseMessage&& certificate);

    Sv2Cipher(bool initiator, std::unique_ptr<Sv2HandshakeState> handshake_state) : m_initiator{initiator}, m_handshake_state{std::move(handshake_state)} {};

    Sv2HandshakeState& GetHandshakeState();
    /**
     * Populates m_hash, m_cs1 and m_cs2 from m_handshake_state and deletes the latter.
     */
    void FinishHandshake();

    /** Decrypts a message. May only be called after FinishHandshake() */
    bool DecryptMessage(std::span<std::byte> ciphertext, std::span<std::byte> plain);
    /** Encrypts a message. May only be called after FinishHandshake() */
    [[nodiscard]] bool EncryptMessage(std::span<const std::byte> input, std::span<std::byte> output);

    /* Expected size after chunking and with MAC */
    static size_t EncryptedMessageSize(const size_t msg_len);

    /* Test only */
    uint256 GetHash() const;

private:
    bool m_initiator;
    std::unique_ptr<Sv2HandshakeState> m_handshake_state;

    uint256 m_hash;
    Sv2CipherState m_cs1;
    Sv2CipherState m_cs2;
};

#endif // BITCOIN_SV2_NOISE_H

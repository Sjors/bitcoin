// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMMON_SV2_NOISE_H
#define BITCOIN_COMMON_SV2_NOISE_H

#include <compat/compat.h>
#include <key.h>
#include <pubkey.h>
#include <streams.h>
#include <uint256.h>

/** The Noise Protocol Framework
 *  https://noiseprotocol.org/noise.html
 *  Revision 38, 2018-07-11
 *
 *  Only parts relevant to Stratum v2 are implemented:
 *  https://github.com/stratum-mining/sv2-spec/blob/main/04-Protocol-Security.md
 */

static constexpr size_t POLY1305_TAGLEN{16};
static constexpr size_t KEY_SIZE = 32;
static constexpr size_t ECDH_OUTPUT_SIZE = 32;
/** Section 3: All Noise messages are less than or equal to 65535 bytes in length. */
static constexpr size_t NOISE_MAX_CHUNK_SIZE = 65535;
/** Sv2 spec 4.5.2 */
static constexpr size_t SIGNATURE_NOISE_MESSAGE_SIZE = 2 + 4 + 4 + 64;
static constexpr size_t INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_LENGTH = KEY_SIZE + KEY_SIZE +
                        POLY1305_TAGLEN + SIGNATURE_NOISE_MESSAGE_SIZE + POLY1305_TAGLEN;

// Sha256 hash of the ascii encoding - "Noise_NX_secp256k1_ChaChaPoly_SHA256".
// This is the first step required when setting up the chaining key.
const std::vector<uint8_t> PROTOCOL_NAME_HASH = {
    168, 246, 65, 106, 218, 197, 235, 205, 62, 183, 118, 131, 234, 247, 6, 174, 180, 164, 162, 125,
    30, 121, 156, 182, 95, 117, 218, 138, 122, 135, 4, 65,
};

// The double hash of protocol name "Noise_NX_secp256k1_ChaChaPoly_SHA256".
static std::vector<uint8_t> PROTOCOL_NAME_DOUBLE_HASH = {132, 175, 109, 74, 47, 106, 167, 237, 124, 169, 128, 188, 123, 69, 19, 92, 215, 4, 100, 205, 0, 191, 211, 210, 38, 190, 247, 183, 20, 200, 116, 58};

class Sv2SignatureNoiseMessage
{
public:
    uint16_t m_version;
    uint32_t m_valid_from;
    uint32_t m_valid_to;
    std::vector<unsigned char> m_sig;

    Sv2SignatureNoiseMessage(uint16_t version, uint32_t valid_from, uint32_t valid_to, const CKey& signing_key);

    void SignSchnorr(uint16_t version, uint32_t valid_from, uint32_t valid_to, const CKey& signing_key, Span<unsigned char> sig);

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        s << m_version
          << m_valid_from
          << m_valid_to;

        s.write(MakeByteSpan(m_sig));
    }
};

/** TODO: delete enum, state machine is handled by Sv2Transport */
enum class SessionState
{
    // The first step of the handshake expects the initiator to send a msg E.
    HANDSHAKE_STEP_1,

    // The second step of the handshake expects the responder to send back a msg ES.
    HANDSHAKE_STEP_2,

    /* Transport state indicates the handshake and cipher confirmation are complete, secure
       communication is in operation. */
    TRANSPORT,
};

class Sv2CipherState
{
public:
    Sv2CipherState() = default;
    explicit Sv2CipherState(uint8_t key[KEY_SIZE]);

    /** Decrypt message
     * @param[in] associated_data associated data
     * @param[in,out] msg message with encrypted and authenticated chunks
     *
     * @returns whether decryption succeeded
     */
     [[nodiscard]] bool DecryptWithAd(Span<const std::byte> associated_data, Span<std::byte> msg);
    void EncryptWithAd(Span<const std::byte> associated_data, Span<std::byte> msg);

    /** The message will be chunked in NOISE_MAX_CHUNK_SIZE parts and expanded
     *  by 16 bytes per chunk for its MAC.
     *
     * @param[in] input     message
     * @param[out] output   message with encrypted and authenticated chunks
     */
    void EncryptMessage(Span<std::byte> input, Span<std::byte> output);

    /** Decrypt message.
     *
     * @param[in] message     message
     */
    [[ nodiscard ]] bool DecryptMessage(Span<std::byte> message);

private:
    uint8_t m_key[KEY_SIZE];
    uint64_t m_nonce = 0;
};

class Sv2SymmetricState
{
public:
    uint8_t m_chaining_key[KEY_SIZE];
    uint256 m_hash_output = uint256(PROTOCOL_NAME_DOUBLE_HASH);

    Sv2SymmetricState() {

        std::memcpy(m_chaining_key, PROTOCOL_NAME_HASH.data(), PROTOCOL_NAME_HASH.size());
    }

    void MixHash(const Span<const std::byte> input);
    void MixKey(const Span<const uint8_t> input_key_material);
    void EncryptAndHash(Span<std::byte> data);
    [[ nodiscard ]] bool DecryptAndHash(Span<std::byte> data);
    std::array<Sv2CipherState, 2> Split();

    /* For testing */
    void LogChainingKey();

private:
    Sv2CipherState m_cipher_state;

    void HKDF2(const Span<const uint8_t> input_key_material, uint8_t out0[KEY_SIZE], uint8_t out1[KEY_SIZE]);

};

struct Sv2NoiseHeader
{
    uint16_t m_header;
    std::vector<std::byte> m_payload;

    Sv2NoiseHeader(uint16_t header) : m_header{header}
    {
        m_payload.resize(m_header);
    }

    Sv2NoiseHeader()
    {
        m_header = 1024;
        m_payload.resize(m_header);
    }

    template <typename T>
    Sv2NoiseHeader(T& input, bool with_mac = true)
    {
        DataStream ss{};
        ss << input;

        auto header = ss.size();
        if (with_mac) {
            header += POLY1305_TAGLEN;
        }
        m_payload.resize(ss.size());

        ss.read(m_payload);

        m_header = header;
        m_payload.resize(m_header);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        s >> m_header;
        m_payload.resize(m_header);
        s.read(m_payload);
    }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        s << m_header
          << Span(m_payload);
    }

};

struct Sv2CipherStateResult
{
    uint256 hash;
    Sv2CipherState cs1;
    Sv2CipherState cs2;
};

class Sv2HandshakeState
{
public:
    XOnlyPubKey m_remote_ephemeral_key;
    XOnlyPubKey m_remote_static_key;
    CKey m_ephemeral_key;
    Sv2SymmetricState m_symmetric_state;

    Sv2HandshakeState() = default;
    Sv2HandshakeState(CKey&& static_key): m_static_key{static_key} {};

    void WriteMsgEphemeralPK(Span<std::byte> msg);
    void ReadMsgEphemeralPK(Span<std::byte> msg);
    /** During handshake Stage 2, put our ephmeral key, static key
      * and certificate in the buffer.
      */
    void WriteMsgES(Span<std::byte> msg);
    /** During handshake Stage 2, read the remote ephmeral key, static key
      * and certificate. Verify their certificate. Only used in test code.
      */
    [[nodiscard]] bool ReadMsgES(Span<std::byte> msg);

private:
    CKey m_static_key;

    void GenerateEphemeralKey(CKey& key) noexcept;
};

class Sv2Cipher
{
public:
    bool m_initiator;

    Sv2Cipher(CKey&& static_key, bool initiator);

    /** TODO: unused after HANDSHAKE state, so clear/remove (std::optional?) */
    std::optional<Sv2HandshakeState> m_handshake_state;

    SessionState m_session_state;

    uint256 m_hash;
    Sv2CipherState m_cs1;
    Sv2CipherState m_cs2;

    bool DecryptMessage(Span<std::byte> message);
    void EncryptMessage(Span<std::byte> input, Span<std::byte> output);
    void FinishHandshake();
};

/** TODO: delete class, have Sv2Transport manage session */
// NoiseSession encapsulates the whole handshake state and subsequent secure
// communication.
class Sv2NoiseSession
{
public:
    Sv2HandshakeState m_handshake_state;

    Sv2NoiseSession(bool initiator, CKey&& static_key);

    /**
     * Process a noise msg to keep a handshake progressing
     * May not be called in TRANSPORT state
     * @throws std::runtime_error if the msg cannot be processed
     * TODO: just return false
     */
    [[ nodiscard ]] bool ProcessMaybeHandshake(Span<std::byte> msg, bool send);

    /** Encrypt a message. Only call in TRANSPORT session state.
     *
     * @param[in] input     message to be encrypted
     * @param[out] output   use EncryptedMessageSize() to get the correct size,
     *                      must point to a different underlying buffer.
     */
    void EncryptMessage(Span<std::byte> input, Span<std::byte> output);

    /** Decrypt a message. Only call in TRANSPORT session state.
     *  The shorter decrypted chunks are concatenated and written
     *  back to msg.
     *
     * @param[in] message   message to be decrypted
     *
     * @returns whether decryption succeeded
     */
    [[ nodiscard ]] bool DecryptMessage(Span<std::byte> message);
    const uint256& GetSymmetricStateHash() const;
    const SessionState& GetSessionState() const;
    bool HandshakeComplete() const
    {
        return m_session_state == SessionState::TRANSPORT;
    }
    /* Expected size after chunking and with MAC */
    static size_t EncryptedMessageSize(size_t msg_len);

private:
    bool m_initiator;

    SessionState m_session_state;

    uint256 m_hash;
    Sv2CipherState m_cs1;
    Sv2CipherState m_cs2;
};

#endif // BITCOIN_COMMON_SV2_NOISE_H

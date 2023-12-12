#ifndef BITCOIN_COMMON_SV2_NOISE_H
#define BITCOIN_COMMON_SV2_NOISE_H

#include <key.h>
#include <logging.h>
#include <crypto/hmac_sha256.h>
#include <crypto/chacha20poly1305.h>
#include <crypto/poly1305.h>
#include <streams.h>

static constexpr size_t POLY1305_TAGLEN{16};
static constexpr size_t KEY_SIZE = 32;
static constexpr size_t ECDH_OUTPUT_SIZE = 32;

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

    Sv2SignatureNoiseMessage(uint16_t version, uint32_t valid_from, uint32_t valid_to, const CKey& signing_key) : m_version{version}, m_valid_from{valid_from}, m_valid_to{valid_to} {
        std::vector<unsigned char> sig;
        const auto sig_size = 64;
        sig.resize(sig_size);

        SignSchnorr(m_version, m_valid_from, m_valid_to, signing_key, sig);
        m_sig = std::move(sig);
    }

    void SignSchnorr(uint16_t version, uint32_t valid_from, uint32_t valid_to, const CKey& signing_key, Span<unsigned char> sig)
    {
        DataStream ss{};
        ss << version
           << valid_from
           << valid_to;

        CSHA256 hasher;
        hasher.Write(reinterpret_cast<unsigned char*>(&(*ss.begin())), ss.end() - ss.begin());

        uint256 hash_output;
        hasher.Finalize(hash_output.begin());

        signing_key.SignSchnorr(hash_output, sig, nullptr, {});
    }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        s << m_version
          << m_valid_from
          << m_valid_to;

        s.write(MakeByteSpan(m_sig));
    }
};

enum class SessionState
{
    // The first step of the handshake expects the initiator to send a msg E.
    HANDSHAKE_STEP_1,

    // The second step of the handshake expects the responder to send back a msg ES.
    HANDSHAKE_STEP_2,

    // After the exchange of keys has completed, each party confirms if a change or
    // cipher upgrade is necessary.
    CIPHER_CONFIRMATION,

    // Transport state indicates the handshake and cipher confirmation are complete, secure
    // communication is in operation.
    TRANSPORT,
};

class Sv2CipherState
{
public:
    Sv2CipherState() = default;
    explicit Sv2CipherState(uint8_t key[KEY_SIZE]);

    void DecryptWithAd(Span<const std::byte> associated_data, Span<std::byte> msg);
    void EncryptWithAd(Span<const std::byte> associated_data, Span<std::byte> msg);

    ssize_t WriteMsg(Span<std::byte> msg);
    ssize_t ReadMsg(Span<std::byte> msg);

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
    void DecryptAndHash(Span<std::byte> data);
    std::array<Sv2CipherState, 2> Split();

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

    ssize_t WriteMsgEphemeralPK(Span<std::byte> msg);
    ssize_t ReadMsgEphemeralPK(Span<std::byte> msg);
    ssize_t WriteMsgES(Span<std::byte> msg);
    ssize_t ReadMsgES(Span<std::byte> msg);

private:
    CKey m_static_key;

    [[nodiscard]] bool GenerateEvenYCoordinateKey(CKey& key);
};

// NoiseSession encapsulates the whole handshake state and subsequent secure
// communication.
class Sv2NoiseSession
{
public:
    Sv2HandshakeState m_handshake_state;

    Sv2NoiseSession(bool initiator, CKey&& static_key);
    ssize_t SendMsg(Span<std::byte> msg);
    ssize_t ReadMsg(Span<std::byte> msg);
    const uint256& GetSymmetricStateHash() const;
    const SessionState& GetSessionState() const;
    bool HandshakeComplete() const
    {
        return m_session_state == SessionState::TRANSPORT;
    }

private:
    bool m_initiator;

    SessionState m_session_state;

    uint256 m_hash;
    Sv2CipherState m_cs1;
    Sv2CipherState m_cs2;

    /**
     * Process a noise msg to either keep a handshake progressing or encrypting
     * and decrypting in the transport state.
     * @throws std::runtime_error if the msg cannot be processed.
     */
    ssize_t ProcessMsg(Span<std::byte> msg, bool send);
};

struct AeadCiphers
{
    uint32_t other_supported_ciphers;

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        // Ignore the first byte since by default, we are not using any other
        // optional ciphers.
        s.ignore(0);
        s >> other_supported_ciphers;
    }
};

struct CipherChoice
{
    uint32_t cipher_choice;

    CipherChoice() = default;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        // We always use the default choice for the ciphers, so simply send 0x00.
        s << static_cast<uint8_t>(0);
    }
};

#endif // BITCOIN_COMMON_SV2_NOISE_H

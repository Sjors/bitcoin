#include <common/sv2_noise.h>

#include <util/check.h>

Sv2CipherState::Sv2CipherState(uint8_t key[KEY_SIZE])
{
    std::copy(key, key + KEY_SIZE, m_key);
}

void Sv2CipherState::DecryptWithAd(Span<const std::byte> associated_data, Span<std::byte> msg)
{
    AEADChaCha20Poly1305::Nonce96 nonce = {0, ++m_nonce};

    auto key = MakeByteSpan(Span(m_key));
    AEADChaCha20Poly1305 aead{key};
    bool res = aead.Decrypt(msg, associated_data, nonce, Span(msg.begin(), msg.end() - POLY1305_TAGLEN));
    if (!res) {
        throw std::runtime_error("Sv2CipherState::DecryptWithAd(): Failed to decrypt message.\n");
    }
}

// The encryption assumes that the msg variable has sufficient space for a 16 byte MAC.
void Sv2CipherState::EncryptWithAd(Span<const std::byte> associated_data, Span<std::byte> msg)
{
    AEADChaCha20Poly1305::Nonce96 nonce = {0, ++m_nonce};

    auto key = MakeByteSpan(Span(m_key));
    AEADChaCha20Poly1305 aead{key};
    aead.Encrypt(Span(msg.begin(), msg.end() - POLY1305_TAGLEN), associated_data, nonce, msg);
}

ssize_t Sv2CipherState::WriteMsg(Span<std::byte> msg)
{
   std::vector<std::byte> empty;
   EncryptWithAd(empty, msg);
   return msg.size();
}

ssize_t Sv2CipherState::ReadMsg(Span<std::byte> msg)
{
   std::vector<std::byte> empty;
   DecryptWithAd(empty, msg);
   return msg.size();
}

void Sv2SymmetricState::MixHash(const Span<const std::byte> input)
{
    m_hash_output = (HashWriter{} << m_hash_output << input).GetSHA256();
}

void Sv2SymmetricState::MixKey(const Span<const uint8_t> input_key_material)
{
    uint8_t out0[KEY_SIZE], out1[KEY_SIZE];

    HKDF2(input_key_material, out0, out1);

    std::memset(m_chaining_key, 0, sizeof(m_chaining_key));
    std::copy(out0, out0 + KEY_SIZE, m_chaining_key);
    m_cipher_state = Sv2CipherState{out1};
}

void Sv2SymmetricState::HKDF2(const Span<const uint8_t> input_key_material, uint8_t out0[KEY_SIZE], uint8_t out1[KEY_SIZE])
{
    uint8_t tmp_key[KEY_SIZE];
    CHMAC_SHA256 tmp_mac(m_chaining_key, KEY_SIZE);
    tmp_mac.Write(input_key_material.begin(), input_key_material.size());
    tmp_mac.Finalize(tmp_key);

    CHMAC_SHA256 out0_mac(tmp_key, KEY_SIZE);
    uint8_t one[1]{0x1};
    out0_mac.Write(one, 1);
    out0_mac.Finalize(out0);

    std::vector<uint8_t> in1;
    in1.reserve(KEY_SIZE + 1);
    std::copy(out0, out0 + KEY_SIZE, std::back_inserter(in1));
    in1.push_back(0x02);

    CHMAC_SHA256 out1_mac(tmp_key, KEY_SIZE);
    out1_mac.Write(&in1[0], in1.size());
    out1_mac.Finalize(out1);
}

void Sv2SymmetricState::EncryptAndHash(Span<std::byte> data)
{
    m_cipher_state.EncryptWithAd(MakeByteSpan(m_hash_output), data);
    MixHash(data);
}

void Sv2SymmetricState::DecryptAndHash(Span<std::byte> data)
{
    // The handshake requires mix hashing the cipher text NOT the decrypted
    // plaintext.
    std::vector<std::byte> cipher_text(data.begin(), data.end());
    m_cipher_state.DecryptWithAd(MakeByteSpan(m_hash_output), data);
    MixHash(cipher_text);
}

std::array<Sv2CipherState, 2> Sv2SymmetricState::Split()
{
    uint8_t send_key[KEY_SIZE], recv_key[KEY_SIZE];

    std::vector<uint8_t> empty;
    HKDF2(empty, send_key, recv_key);

    std::array<Sv2CipherState, 2> result;
    result[0] = Sv2CipherState{send_key};
    result[1] = Sv2CipherState{recv_key};

    return result;
}

ssize_t Sv2HandshakeState::WriteMsgEphemeralPK(Span<std::byte> msg)
{
    Assume(msg.size() >= KEY_SIZE);

    if (!GenerateEvenYCoordinateKey(m_ephemeral_key)) {
        throw std::runtime_error("Failed to generate a ephemeral key with a even Y coordinate");
    }

    auto ephemeral_pk = XOnlyPubKey(m_ephemeral_key.GetPubKey());
    std::transform(ephemeral_pk.begin(), ephemeral_pk.end(), msg.begin(),
               [](unsigned char b) { return static_cast<std::byte>(b); });

    m_symmetric_state.MixHash(Span(msg.begin(), KEY_SIZE));

    std::vector<std::byte> empty;
    m_symmetric_state.MixHash(empty);

    return KEY_SIZE;
}

ssize_t Sv2HandshakeState::ReadMsgEphemeralPK(Span<std::byte> msg) {
    auto ucharSpan = UCharSpanCast(msg);
    m_remote_ephemeral_key = XOnlyPubKey(Span(&ucharSpan[0], KEY_SIZE));

    if (!m_remote_ephemeral_key.IsFullyValid()) {
       throw std::runtime_error("Sv2HandshakeState::ReadMsgEphemeralPK(): Received invalid remote ephemeral key");
    }
    m_symmetric_state.MixHash(Span(&msg[0], KEY_SIZE));

    std::vector<std::byte> empty;
    m_symmetric_state.MixHash(empty);

    return KEY_SIZE;
}

ssize_t Sv2HandshakeState::WriteMsgES(Span<std::byte> msg)
{
    ssize_t bytes_written = 0;

    if (!GenerateEvenYCoordinateKey(m_ephemeral_key)) {
        throw std::runtime_error("Failed to generate a ephemeral key with a even Y coordinate");
    }

    // Send our ephemeral pk.
    auto ephemeral_pk = XOnlyPubKey(m_ephemeral_key.GetPubKey());
    std::transform(ephemeral_pk.begin(), ephemeral_pk.end(), msg.begin(),
               [](unsigned char b) { return static_cast<std::byte>(b); });

    m_symmetric_state.MixHash(Span(msg.begin(), KEY_SIZE));
    bytes_written += KEY_SIZE;

    uint8_t ecdh_output[ECDH_OUTPUT_SIZE] = {};
    if (!m_ephemeral_key.ECDH(m_remote_ephemeral_key, ecdh_output)) {
        throw std::runtime_error("Failed to perform ECDH on the remote ephemeral key using our ephemeral key");
    }
    m_symmetric_state.MixKey(Span(ecdh_output));

    // Send our static pk.
    auto static_pk = XOnlyPubKey(m_static_key.GetPubKey());
    std::transform(static_pk.begin(), static_pk.end(), msg.begin() + KEY_SIZE,
               [](unsigned char b) { return static_cast<std::byte>(b); });
    m_symmetric_state.EncryptAndHash(Span(msg.begin() + KEY_SIZE, KEY_SIZE + POLY1305_TAGLEN));
    bytes_written += KEY_SIZE + POLY1305_TAGLEN;

    uint8_t ecdh_output_remote[ECDH_OUTPUT_SIZE];
    if (!m_static_key.ECDH(m_remote_ephemeral_key, ecdh_output_remote)) {
        throw std::runtime_error("Failed to perform ECDH on the remote ephemeral key using our static key");
    }
    m_symmetric_state.MixKey(Span(ecdh_output_remote));

    // Add our digital signature noise message.
    auto epoch_now = std::chrono::system_clock::now().time_since_epoch();
    uint32_t valid_from = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(epoch_now).count());
    // TODO: Move hardcoding into Sv2SignatureNoiseMessage constructor or an option to change validity length.
    auto one_year_unix = 31536000;
    uint32_t valid_to = valid_from + one_year_unix;
    uint16_t version = 0;
    // TODO: Authority key needs to be uploaded to be used in the signature noise message.
    auto sig_noise_msg = Sv2SignatureNoiseMessage(version, valid_from, valid_to, m_static_key);

    // Serialize our digital signature noise message and encrypt.
    DataStream ss{};
    ss << sig_noise_msg;
    auto sig_noise_size = ss.size();
    std::copy(ss.begin(), ss.end(), msg.begin() + bytes_written);

    m_symmetric_state.EncryptAndHash(Span(msg.begin() + bytes_written, sig_noise_size + POLY1305_TAGLEN));

    bytes_written += sig_noise_size + POLY1305_TAGLEN;

    return bytes_written;
}

ssize_t Sv2HandshakeState::ReadMsgES(Span<std::byte> msg)
{

   ssize_t bytes_read = 0;

   // Read the remote ephmeral key from the msg and decrypt.
   auto remote_ephemeral_key_span = UCharSpanCast(Span(msg.begin(), KEY_SIZE));
   m_remote_ephemeral_key = XOnlyPubKey(remote_ephemeral_key_span);
    if (!m_remote_ephemeral_key.IsFullyValid()) {
       throw std::runtime_error("Sv2HandshakeState::ReadMsgES(): Received invalid remote ephemeral key");
    }
   bytes_read += KEY_SIZE;

   m_symmetric_state.MixHash(Span(msg.begin(), KEY_SIZE));

   uint8_t ecdh_output[ECDH_OUTPUT_SIZE];
   m_ephemeral_key.ECDH(m_remote_ephemeral_key, ecdh_output);

   m_symmetric_state.MixKey(Span(ecdh_output));

   m_symmetric_state.DecryptAndHash(Span(msg.begin() + KEY_SIZE, KEY_SIZE + POLY1305_TAGLEN));
   bytes_read += KEY_SIZE + POLY1305_TAGLEN;

   // Read the remote static key from the msg and decrypt.
   auto remote_static_key_span = UCharSpanCast(Span(msg.begin() + KEY_SIZE, KEY_SIZE));
   m_remote_static_key = XOnlyPubKey(remote_static_key_span);

   if (!m_remote_static_key.IsFullyValid()) {
       throw std::runtime_error("Sv2HandshakeState::ReadMsgES(): Received invalid remote static key");
   }

   uint8_t ecdh_output_remote[ECDH_OUTPUT_SIZE];
   if (!m_ephemeral_key.ECDH(m_remote_static_key, ecdh_output_remote)) {
        throw std::runtime_error("Failed to perform ECDH on the remote static key using our ephemeral key");

   }
   m_symmetric_state.MixKey(Span(ecdh_output_remote));

   // TODO: Validate the decrypted digital signature noise message
   auto constexpr digital_sig_len = 74;
   m_symmetric_state.DecryptAndHash(Span(msg.begin() + bytes_read, digital_sig_len + POLY1305_TAGLEN));
   bytes_read += (digital_sig_len + POLY1305_TAGLEN);

   return bytes_read;
}

ssize_t Sv2NoiseSession::ProcessMsg(Span<std::byte> msg, bool send)
{
    ssize_t num_bytes = 0;
    switch (m_session_state)
    {
        case SessionState::HANDSHAKE_STEP_1:
        {
            if (send) {
                num_bytes = m_handshake_state.WriteMsgEphemeralPK(msg);
            } else {
                num_bytes = m_handshake_state.ReadMsgEphemeralPK(msg);
            }

            m_session_state = SessionState::HANDSHAKE_STEP_2;
            break;
        }
        case SessionState::HANDSHAKE_STEP_2:
        {
            if (send) {
                num_bytes = m_handshake_state.WriteMsgES(msg);
            } else {
                num_bytes = m_handshake_state.ReadMsgES(msg);
            }

           auto cipher_state = m_handshake_state.m_symmetric_state.Split();
           auto cs1 = cipher_state[0];
           auto cs2 = cipher_state[1];

           m_hash = std::move(m_handshake_state.m_symmetric_state.m_hash_output);
           m_cs1 = std::move(cs1);
           m_cs2 = std::move(cs2);

           m_session_state = SessionState::CIPHER_CONFIRMATION;
           break;
        }
        case SessionState::CIPHER_CONFIRMATION:
        {
           num_bytes = 1; // Cipher choice by default only serializes on byte for Bitcoin.
           DataStream ss_output{};
           if (send) {
               CipherChoice cipher_choice;
               ss_output << cipher_choice;
               std::memcpy(&msg[0], &ss_output[0], num_bytes);
           } else {
               AeadCiphers ciphers;
               DataStream ss_received_ciphers(msg);
               ss_received_ciphers >> ciphers;

               CipherChoice cipher_choice;
               ss_output << cipher_choice;
               std::memcpy(&msg[0], &ss_output[0], num_bytes);
           }

           m_session_state = SessionState::TRANSPORT;
           break;
        }
        case SessionState::TRANSPORT:
        {
            if (send) {
                if (m_initiator) {
                    num_bytes = m_cs1.WriteMsg(msg);
                } else {
                    num_bytes = m_cs2.WriteMsg(msg);
                }
            } else {
                if (m_initiator) {
                    num_bytes = m_cs2.ReadMsg(msg);
                } else {
                    num_bytes = m_cs1.ReadMsg(msg);
                }
            }
            break;
        }
    }

    return num_bytes;
}

Sv2NoiseSession::Sv2NoiseSession(bool initiator, CKey&& static_key): m_initiator{initiator}
{
   m_handshake_state = Sv2HandshakeState(std::move(static_key));
   m_session_state = SessionState::HANDSHAKE_STEP_1;
}

ssize_t Sv2NoiseSession::SendMsg(Span<std::byte> msg)
{
    // TODO: msg len error handling
    return ProcessMsg(msg, true /*send*/);
}

ssize_t Sv2NoiseSession::ReadMsg(Span<std::byte> msg)
{
    // TODO: msg len error handling
    return ProcessMsg(msg, false /*send*/);
}

const uint256& Sv2NoiseSession::GetSymmetricStateHash() const
{
    return m_hash;
}

const SessionState& Sv2NoiseSession::GetSessionState() const
{
    return m_session_state;
}

bool Sv2HandshakeState::GenerateEvenYCoordinateKey(CKey& key)
{
    if (!key.IsValid()) {
        key.MakeNewKey(true);
    }

    // Set an upper bound on the number of attempts.
    constexpr int maxAttempts = 1000;
    int attempts = 0;
    while (!key.HasEvenY() && attempts < maxAttempts) {
        key.MakeNewKey(true);
    }

    return key.HasEvenY();
};

// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/sv2_noise.h>
#include <logging.h>
#include <span.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/util/setup_common.h>
#include <test/fuzz/util.h>
#include <test/util/xoroshiro128plusplus.h>


#include <cstdint>
#include <util/vector.h>


namespace {


void Initialize()
{
    // Add test context for debugging. Usage:
    // --debug=sv2 --loglevel=sv2:trace --printtoconsole=1
    static const auto testing_setup = std::make_unique<const BasicTestingSetup>();
}
}  // namespace

FUZZ_TARGET(sv2_noise_cipher_roundtrip, .init=Initialize)
{
    // Test that Sv2Noise's encryption and decryption agree.

    // To conserve fuzzer entropy, deterministically generate Alice and Bob keys.
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    auto seed_ent = provider.ConsumeBytes<std::byte>(32);
    seed_ent.resize(32);
    CExtKey seed;
    seed.SetSeed(seed_ent);

    CExtKey tmp;
    if (!seed.Derive(tmp, 0)) return;
    CKey alice_authority_key{tmp.key};

    if (!seed.Derive(tmp, 1)) return;
    CKey alice_static_key{tmp.key};

    if (!seed.Derive(tmp, 2)) return;
    CKey alice_ephemeral_key{tmp.key};

    if (!seed.Derive(tmp, 10)) return;
    CKey bob_authority_key{tmp.key};

    if (!seed.Derive(tmp, 11)) return;
    CKey bob_static_key{tmp.key};

    if (!seed.Derive(tmp, 12)) return;
    CKey bob_ephemeral_key{tmp.key};

    // Create certificate
    // Pick random times in the past or future well outside the grace window.
    uint32_t now = provider.ConsumeIntegralInRange<uint32_t>(10000, UINT32_MAX);
    SetMockTime(now);
    int32_t time_offset = provider.ConsumeIntegralInRange(-static_cast<int32_t>(SV2_CERTIFICATE_GRACE_PERIOD),
                                                          static_cast<int32_t>(SV2_CERTIFICATE_GRACE_PERIOD));
    uint16_t version = provider.ConsumeBool() ? 0 : provider.ConsumeIntegral<uint16_t>();
    uint32_t past = provider.ConsumeIntegralInRange<uint32_t>(0, now);
    uint32_t future = provider.ConsumeIntegralInRange<uint32_t>(now, UINT32_MAX);
    uint32_t valid_from = time_offset + (provider.ConsumeBool() ? past : future);
    uint32_t valid_to = time_offset + (provider.ConsumeBool() ? future : past);

   // TODO: Stratum v2 spec requires signing the static key using the authority key,
    //       but SRI currently implements this incorrectly.
    bob_authority_key = bob_static_key;
    auto bob_certificate = Sv2SignatureNoiseMessage(version, valid_from, valid_to,
                             XOnlyPubKey(bob_static_key.GetPubKey()), bob_authority_key);

    bool valid_certificate = version == 0 &&
                             (valid_from <= now + SV2_CERTIFICATE_GRACE_PERIOD) &&
                             (valid_to >= now - SV2_CERTIFICATE_GRACE_PERIOD);

    LogPrintLevel(BCLog::SV2, BCLog::Level::Trace,  "valid_certificate: %d - version %u, past: %u, now %u, future: %u\n", valid_certificate, version, past, now, future);

    // Alice's static is not used in the test
    // Alice needs to verify Bob's certificate, so we pass his authority key
    auto alice_handshake = std::make_unique<Sv2HandshakeState>(std::move(alice_static_key), XOnlyPubKey(bob_authority_key.GetPubKey()));
    alice_handshake->SetEphemeralKey(std::move(alice_ephemeral_key));
    // Bob is the responder and does not receive (or verify) Alice's certificate,
    // so we don't pass her authority key.
    auto bob_handshake = std::make_unique<Sv2HandshakeState>(std::move(bob_static_key), std::move(bob_certificate));
    bob_handshake->SetEphemeralKey(std::move(bob_ephemeral_key));

    // Handshake Act 1: e ->

    std::vector<uint8_t> transport_buffer;
    transport_buffer.resize(KEY_SIZE);
    Span<std::byte> transport_span{MakeWritableByteSpan(transport_buffer)};
    // Alice generates her ephemeral public key and write it into the buffer:
    alice_handshake->WriteMsgEphemeralPK(transport_span);
    XOnlyPubKey alice_pubkey(Span(&transport_buffer[0], XOnlyPubKey::size()));

    // Bob reads the ephemeral key
    // TODO: mess with bytes on the wire
    bob_handshake->ReadMsgEphemeralPK(transport_span);
    ClearShrink(transport_buffer);

    // Handshake Act 2: <- e, ee, s, es, SIGNATURE_NOISE_MESSAGE
    transport_buffer.resize(INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_LENGTH);
    transport_span = MakeWritableByteSpan(transport_buffer);
    bob_handshake->WriteMsgES(transport_span);

    assert(alice_handshake->ReadMsgES(transport_span) == valid_certificate);

    // Construct Sv2Cipher from the Sv2HandshakeState and test transport
    auto alice{Sv2Cipher(/*initiator=*/true, std::move(alice_handshake))};
    auto bob{Sv2Cipher(/*initiator=*/false, std::move(bob_handshake))};
    alice.FinishHandshake();
    bob.FinishHandshake();

    ClearShrink(transport_buffer);

    const std::vector<uint8_t> TEST = { // hello world
        0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64,
    };

    const size_t encrypted_size = Sv2Cipher::EncryptedMessageSize(TEST.size());

    transport_buffer.resize(encrypted_size);
    transport_span = MakeWritableByteSpan(transport_buffer);

    auto plain_send{MakeByteSpan(TEST)};
    alice.EncryptMessage(plain_send, transport_span);

    // TODO: mess with wire bytes
    assert(bob.DecryptMessage(transport_span));
    std::vector<uint8_t> bob_read;
    bob_read.resize(TEST.size());
    std::transform(transport_span.begin(), transport_span.subspan(0, TEST.size()).end(), bob_read.begin(),
               [](std::byte b) { return static_cast<uint8_t>(b); });
    assert(bob_read == TEST);

    // // Initialize ciphers by exchanging public keys.
    // BIP324Cipher initiator(init_key, init_ent);
    // assert(!initiator);
    // BIP324Cipher responder(resp_key, resp_ent);
    // assert(!responder);
    // initiator.Initialize(responder.GetOurPubKey(), true);
    // assert(initiator);
    // responder.Initialize(initiator.GetOurPubKey(), false);
    // assert(responder);


    // // Initialize RNG deterministically, to generate contents and AAD. We assume that there are no
    // // (potentially buggy) edge cases triggered by specific values of contents/AAD, so we can avoid
    // // reading the actual data for those from the fuzzer input (which would need large amounts of
    // // data).
    // XoRoShiRo128PlusPlus rng(provider.ConsumeIntegral<uint64_t>());

    // // Compare session IDs and garbage terminators.
    // assert(initiator.GetSessionID() == responder.GetSessionID());
    // assert(initiator.GetSendGarbageTerminator() == responder.GetReceiveGarbageTerminator());
    // assert(initiator.GetReceiveGarbageTerminator() == responder.GetSendGarbageTerminator());

    // LIMITED_WHILE(provider.remaining_bytes(), 1000) {
    //     // Mode:
    //     // - Bit 0: whether the ignore bit is set in message
    //     // - Bit 1: whether the responder (0) or initiator (1) sends
    //     // - Bit 2: whether this ciphertext will be corrupted (making it the last sent one)
    //     // - Bit 3-4: controls the maximum aad length (max 4095 bytes)
    //     // - Bit 5-7: controls the maximum content length (max 16383 bytes, for performance reasons)
    //     unsigned mode = provider.ConsumeIntegral<uint8_t>();
    //     bool ignore = mode & 1;
    //     bool from_init = mode & 2;
    //     bool damage = mode & 4;
    //     unsigned aad_length_bits = 4 * ((mode >> 3) & 3);
    //     unsigned aad_length = provider.ConsumeIntegralInRange<unsigned>(0, (1 << aad_length_bits) - 1);
    //     unsigned length_bits = 2 * ((mode >> 5) & 7);
    //     unsigned length = provider.ConsumeIntegralInRange<unsigned>(0, (1 << length_bits) - 1);
    //     // Generate aad and content.
    //     std::vector<std::byte> aad(aad_length);
    //     for (auto& val : aad) val = std::byte{(uint8_t)rng()};
    //     std::vector<std::byte> contents(length);
    //     for (auto& val : contents) val = std::byte{(uint8_t)rng()};

    //     // Pick sides.
    //     auto& sender{from_init ? initiator : responder};
    //     auto& receiver{from_init ? responder : initiator};

    //     // Encrypt
    //     std::vector<std::byte> ciphertext(length + initiator.EXPANSION);
    //     sender.Encrypt(contents, aad, ignore, ciphertext);

    //     // Optionally damage 1 bit in either the ciphertext (corresponding to a change in transit)
    //     // or the aad (to make sure that decryption will fail if the AAD mismatches).
    //     if (damage) {
    //         unsigned damage_bit = provider.ConsumeIntegralInRange<unsigned>(0,
    //             (ciphertext.size() + aad.size()) * 8U - 1U);
    //         unsigned damage_pos = damage_bit >> 3;
    //         std::byte damage_val{(uint8_t)(1U << (damage_bit & 7))};
    //         if (damage_pos >= ciphertext.size()) {
    //             aad[damage_pos - ciphertext.size()] ^= damage_val;
    //         } else {
    //             ciphertext[damage_pos] ^= damage_val;
    //         }
    //     }

    //     // Decrypt length
    //     uint32_t dec_length = receiver.DecryptLength(Span{ciphertext}.first(initiator.LENGTH_LEN));
    //     if (!damage) {
    //         assert(dec_length == length);
    //     } else {
    //         // For performance reasons, don't try to decode if length got increased too much.
    //         if (dec_length > 16384 + length) break;
    //         // Otherwise, just append zeros if dec_length > length.
    //         ciphertext.resize(dec_length + initiator.EXPANSION);
    //     }

    //     // Decrypt
    //     std::vector<std::byte> decrypt(dec_length);
    //     bool dec_ignore{false};
    //     bool ok = receiver.Decrypt(Span{ciphertext}.subspan(initiator.LENGTH_LEN), aad, dec_ignore, decrypt);
    //     // Decryption *must* fail if the packet was damaged, and succeed if it wasn't.
    //     assert(!ok == damage);
    //     if (!ok) break;
    //     assert(ignore == dec_ignore);
    //     assert(decrypt == contents);
    // }
}

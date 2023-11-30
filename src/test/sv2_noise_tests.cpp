#include <common/sv2_noise.h>
#include <key.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(sv2_noise_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(MixKey_test)
{
    Sv2SymmetricState i_ss;
    Sv2SymmetricState r_ss;
    BOOST_CHECK(std::memcmp(&r_ss.m_chaining_key, &i_ss.m_chaining_key, 32) == 0);

    CKey initiator_key;
    initiator_key.MakeNewKey(true);
    while (!initiator_key.HasEvenY()) {
        initiator_key.MakeNewKey(true);
    }
    BOOST_CHECK(initiator_key.HasEvenY());
    auto initiator_pk = XOnlyPubKey(initiator_key.GetPubKey());

    CKey responder_key;
    responder_key.MakeNewKey(true);
    while (!responder_key.HasEvenY()) {
        responder_key.MakeNewKey(true);
    }
    BOOST_CHECK(responder_key.HasEvenY());
    auto responder_pk = XOnlyPubKey(responder_key.GetPubKey());

    unsigned char ecdh_output_1[32];
    initiator_key.ECDH(responder_pk, ecdh_output_1);


    unsigned char ecdh_output_2[32];
    responder_key.ECDH(initiator_pk, ecdh_output_2);

    BOOST_CHECK(std::memcmp(&ecdh_output_1[0], &ecdh_output_2[0], 32) == 0);

    i_ss.MixKey(Span(ecdh_output_1));
    r_ss.MixKey(Span(ecdh_output_2));

    BOOST_CHECK(std::memcmp(&r_ss.m_chaining_key, &i_ss.m_chaining_key, 32) == 0);
}

BOOST_AUTO_TEST_CASE(handshake_test)
{
    CKey static_key;
    static_key.MakeNewKey(true);
    while (!static_key.HasEvenY()) {
        static_key.MakeNewKey(true);
    }
    BOOST_CHECK(static_key.HasEvenY());

    Sv2NoiseSession noise_initiator{/*initiator=*/true, std::move(static_key)};

    // Send the first part of the handshake: e ->
    Sv2NoiseHeader msg_e;
    auto num_bytes = noise_initiator.SendMsg(msg_e.m_payload);
    msg_e.m_header = num_bytes;

    auto valid_pubkey_bytes = UCharSpanCast(Span(msg_e.m_payload));
    XOnlyPubKey valid_pubkey(Span(&valid_pubkey_bytes[0], XOnlyPubKey::size()));
    BOOST_CHECK(valid_pubkey.IsFullyValid());

    // Assert that sharing the ephemeral publickey of the initiator with responder
    // results in the same symmetric state.
    CKey responder_static_key;
    responder_static_key.MakeNewKey(true);
    while (!responder_static_key.HasEvenY()) {
        responder_static_key.MakeNewKey(true);
    }
    BOOST_CHECK(responder_static_key.HasEvenY());

    Sv2NoiseSession noise_responder{false /*initiator*/, std::move(responder_static_key)};
    noise_responder.ReadMsg(msg_e.m_payload);

    // Assert that the responder receives the same key that was sent.
    BOOST_CHECK(XOnlyPubKey(noise_initiator.m_handshake_state.m_ephemeral_key.GetPubKey()) == noise_responder.m_handshake_state.m_remote_ephemeral_key);

    // Assert both initiator and responder reach the same state.
    BOOST_CHECK_EQUAL(noise_initiator.GetSymmetricStateHash(), noise_responder.GetSymmetricStateHash());
    BOOST_CHECK_EQUAL(noise_initiator.GetSessionState(), SessionState::HANDSHAKE_STEP_2);
    BOOST_CHECK_EQUAL(noise_responder.GetSessionState(), SessionState::HANDSHAKE_STEP_2);

    // Responder send back the second part of the handshake: <- e, ee, s, es
    Sv2NoiseHeader msg_es;
    num_bytes = noise_responder.SendMsg(msg_es.m_payload);
    msg_es.m_header = num_bytes;

    BOOST_CHECK_EQUAL(noise_responder.GetSessionState(), SessionState::CIPHER_CONFIRMATION);

    // Initiator receives the send part of the handshake and generates symmetric states.
    noise_initiator.ReadMsg(msg_es.m_payload);
    BOOST_CHECK(noise_initiator.m_handshake_state.m_remote_ephemeral_key == XOnlyPubKey(noise_responder.m_handshake_state.m_ephemeral_key.GetPubKey()));
    BOOST_CHECK_EQUAL(noise_initiator.GetSessionState(), SessionState::CIPHER_CONFIRMATION);
    BOOST_CHECK_EQUAL(noise_initiator.GetSymmetricStateHash(), noise_responder.GetSymmetricStateHash());


    // It should confirm the ciphers used in the secure communication.
    Sv2NoiseHeader cipher_options;
    num_bytes = noise_initiator.SendMsg(cipher_options.m_payload);
    cipher_options.m_header = num_bytes;

    num_bytes = noise_responder.ReadMsg(cipher_options.m_payload);

    BOOST_CHECK_EQUAL(noise_initiator.GetSessionState(), SessionState::TRANSPORT);
    BOOST_CHECK_EQUAL(noise_responder.GetSessionState(), SessionState::TRANSPORT);

    // Assert that both parties can communicate using secure transport.
    Sv2NoiseHeader transport_header{255};
    auto plaintext = transport_header.m_payload;

    BOOST_CHECK_EQUAL(transport_header.m_payload.size(), plaintext.size());
    BOOST_CHECK(std::equal(transport_header.m_payload.begin(), transport_header.m_payload.end(), plaintext.begin()));

    noise_initiator.SendMsg(transport_header.m_payload);
    BOOST_CHECK_EQUAL(transport_header.m_payload.size(), plaintext.size());
    BOOST_CHECK(!std::equal(transport_header.m_payload.begin(), transport_header.m_payload.end(), plaintext.begin()));

    // It should decrypt the bytes back to the plainted. The HMAC is validated within calls of ReadMsg.
    noise_responder.ReadMsg(transport_header.m_payload);
    BOOST_CHECK_EQUAL(transport_header.m_payload.size(), plaintext.size());
    BOOST_CHECK(std::equal(transport_header.m_payload.begin(), transport_header.m_payload.end() - 16, plaintext.begin()));
}
BOOST_AUTO_TEST_SUITE_END()

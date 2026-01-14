// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_CHACHA20POLY1305_H
#define BITCOIN_CRYPTO_CHACHA20POLY1305_H

#include <cstddef>
#include <cstdint>
#include <span>

#include <crypto/chacha20.h>
#include <crypto/poly1305.h>

/** The AEAD_CHACHA20_POLY1305 authenticated encryption algorithm from RFC8439 section 2.8. */
class AEADChaCha20Poly1305
{
    /** Internal stream cipher. */
    ChaCha20 m_chacha20;

public:
    /** Expected size of key argument in constructor. */
    static constexpr unsigned KEYLEN = 32;

    /** Expansion when encrypting. */
    static constexpr unsigned EXPANSION = Poly1305::TAGLEN;

    /** Initialize an AEAD instance with a specified 32-byte key. */
    AEADChaCha20Poly1305(std::span<const std::byte> key) noexcept;

    /** Switch to another 32-byte key. */
    void SetKey(std::span<const std::byte> key) noexcept;

    /** 96-bit nonce type. */
    using Nonce96 = ChaCha20::Nonce96;

    /** Size of the nonce in bytes. */
    static constexpr unsigned NONCE_SIZE = 12;

    /** Convert a 12-byte array to a Nonce96.
     *
     * RFC8439 defines the nonce as 96 opaque bits. This helper converts
     * a byte array (big-endian) to the internal {uint32_t, uint64_t} representation.
     */
    static Nonce96 NonceFromBytes(std::span<const std::byte, NONCE_SIZE> nonce_bytes) noexcept
    {
        return {
            (uint32_t(uint8_t(nonce_bytes[0])) << 24) | (uint32_t(uint8_t(nonce_bytes[1])) << 16) |
            (uint32_t(uint8_t(nonce_bytes[2])) << 8) | uint32_t(uint8_t(nonce_bytes[3])),
            (uint64_t(uint8_t(nonce_bytes[4])) << 56) | (uint64_t(uint8_t(nonce_bytes[5])) << 48) |
            (uint64_t(uint8_t(nonce_bytes[6])) << 40) | (uint64_t(uint8_t(nonce_bytes[7])) << 32) |
            (uint64_t(uint8_t(nonce_bytes[8])) << 24) | (uint64_t(uint8_t(nonce_bytes[9])) << 16) |
            (uint64_t(uint8_t(nonce_bytes[10])) << 8) | uint64_t(uint8_t(nonce_bytes[11]))
        };
    }

    /** Convert a Nonce96 back to a 12-byte array (big-endian). */
    static void NonceToBytes(Nonce96 nonce, std::span<std::byte, NONCE_SIZE> nonce_bytes) noexcept
    {
        nonce_bytes[0] = std::byte((nonce.first >> 24) & 0xFF);
        nonce_bytes[1] = std::byte((nonce.first >> 16) & 0xFF);
        nonce_bytes[2] = std::byte((nonce.first >> 8) & 0xFF);
        nonce_bytes[3] = std::byte(nonce.first & 0xFF);
        nonce_bytes[4] = std::byte((nonce.second >> 56) & 0xFF);
        nonce_bytes[5] = std::byte((nonce.second >> 48) & 0xFF);
        nonce_bytes[6] = std::byte((nonce.second >> 40) & 0xFF);
        nonce_bytes[7] = std::byte((nonce.second >> 32) & 0xFF);
        nonce_bytes[8] = std::byte((nonce.second >> 24) & 0xFF);
        nonce_bytes[9] = std::byte((nonce.second >> 16) & 0xFF);
        nonce_bytes[10] = std::byte((nonce.second >> 8) & 0xFF);
        nonce_bytes[11] = std::byte(nonce.second & 0xFF);
    }

    /** Encrypt a message with a specified 96-bit nonce and aad.
     *
     * Requires cipher.size() = plain.size() + EXPANSION.
     */
    void Encrypt(std::span<const std::byte> plain, std::span<const std::byte> aad, Nonce96 nonce, std::span<std::byte> cipher) noexcept
    {
        Encrypt(plain, {}, aad, nonce, cipher);
    }

    /** Encrypt a message (given split into plain1 + plain2) with a specified 96-bit nonce and aad.
     *
     * Requires cipher.size() = plain1.size() + plain2.size() + EXPANSION.
     */
    void Encrypt(std::span<const std::byte> plain1, std::span<const std::byte> plain2, std::span<const std::byte> aad, Nonce96 nonce, std::span<std::byte> cipher) noexcept;

    /** Decrypt a message with a specified 96-bit nonce and aad. Returns true if valid.
     *
     * Requires cipher.size() = plain.size() + EXPANSION.
     */
    bool Decrypt(std::span<const std::byte> cipher, std::span<const std::byte> aad, Nonce96 nonce, std::span<std::byte> plain) noexcept
    {
        return Decrypt(cipher, aad, nonce, plain, {});
    }

    /** Decrypt a message with a specified 96-bit nonce and aad and split the result. Returns true if valid.
     *
     * Requires cipher.size() = plain1.size() + plain2.size() + EXPANSION.
     */
    bool Decrypt(std::span<const std::byte> cipher, std::span<const std::byte> aad, Nonce96 nonce, std::span<std::byte> plain1, std::span<std::byte> plain2) noexcept;

    /** Get a number of keystream bytes from the underlying stream cipher.
     *
     * This is equivalent to Encrypt() with plain set to that many zero bytes, and dropping the
     * last EXPANSION bytes off the result.
     */
    void Keystream(Nonce96 nonce, std::span<std::byte> keystream) noexcept;
};

/** Forward-secure wrapper around AEADChaCha20Poly1305.
 *
 * This implements an AEAD which automatically increments the nonce on every encryption or
 * decryption, and cycles keys after a predetermined number of encryptions or decryptions.
 *
 * See BIP324 for details.
 */
class FSChaCha20Poly1305
{
private:
    /** Internal AEAD. */
    AEADChaCha20Poly1305 m_aead;

    /** Every how many iterations this cipher rekeys. */
    const uint32_t m_rekey_interval;

    /** The number of encryptions/decryptions since the last rekey. */
    uint32_t m_packet_counter{0};

    /** The number of rekeys performed so far. */
    uint64_t m_rekey_counter{0};

    /** Update counters (and if necessary, key) to transition to the next message. */
    void NextPacket() noexcept;

public:
    /** Length of keys expected by the constructor. */
    static constexpr auto KEYLEN = AEADChaCha20Poly1305::KEYLEN;

    /** Expansion when encrypting. */
    static constexpr auto EXPANSION = AEADChaCha20Poly1305::EXPANSION;

    // No copy or move to protect the secret.
    FSChaCha20Poly1305(const FSChaCha20Poly1305&) = delete;
    FSChaCha20Poly1305(FSChaCha20Poly1305&&) = delete;
    FSChaCha20Poly1305& operator=(const FSChaCha20Poly1305&) = delete;
    FSChaCha20Poly1305& operator=(FSChaCha20Poly1305&&) = delete;

    /** Construct an FSChaCha20Poly1305 cipher that rekeys every rekey_interval operations. */
    FSChaCha20Poly1305(std::span<const std::byte> key, uint32_t rekey_interval) noexcept :
        m_aead(key), m_rekey_interval(rekey_interval) {}

    /** Encrypt a message with a specified aad.
     *
     * Requires cipher.size() = plain.size() + EXPANSION.
     */
    void Encrypt(std::span<const std::byte> plain, std::span<const std::byte> aad, std::span<std::byte> cipher) noexcept
    {
        Encrypt(plain, {}, aad, cipher);
    }

    /** Encrypt a message (given split into plain1 + plain2) with a specified aad.
     *
     * Requires cipher.size() = plain.size() + EXPANSION.
     */
    void Encrypt(std::span<const std::byte> plain1, std::span<const std::byte> plain2, std::span<const std::byte> aad, std::span<std::byte> cipher) noexcept;

    /** Decrypt a message with a specified aad. Returns true if valid.
     *
     * Requires cipher.size() = plain.size() + EXPANSION.
     */
    bool Decrypt(std::span<const std::byte> cipher, std::span<const std::byte> aad, std::span<std::byte> plain) noexcept
    {
        return Decrypt(cipher, aad, plain, {});
    }

    /** Decrypt a message with a specified aad and split the result. Returns true if valid.
     *
     * Requires cipher.size() = plain1.size() + plain2.size() + EXPANSION.
     */
    bool Decrypt(std::span<const std::byte> cipher, std::span<const std::byte> aad, std::span<std::byte> plain1, std::span<std::byte> plain2) noexcept;
};

#endif // BITCOIN_CRYPTO_CHACHA20POLY1305_H

// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INDEX_TXINDEX_KEY_H
#define BITCOIN_INDEX_TXINDEX_KEY_H

#include <consensus/consensus.h>
#include <crypto/siphash.h>
#include <serialize.h>
#include <uint256.h>

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <ios>

namespace txindex {
constexpr uint8_t DB_TXINDEX_HASHED{'x'};

using TxHashKeyPrefix = std::array<uint8_t, 5>;

//! The location of a transaction: the height of the block that contains it and the
//! transaction's byte offset within that block (after the header).
//!
//! Since the offset must always be less than the max block serialized size, we can
//! pack the position into a single integer code = max_block_size * height + offset
//! and split apart as (height = code / max_block_size, offset = code % max_block_size).
struct Position {
    uint32_t block_height{0};
    uint32_t tx_offset{0};

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        assert(tx_offset < MAX_BLOCK_SERIALIZED_SIZE);
        const uint64_t code{uint64_t{MAX_BLOCK_SERIALIZED_SIZE} * block_height + tx_offset};
        size_t width{1};
        for (uint64_t v{code >> 8}; v != 0; v >>= 8) ++width;
        for (size_t shift{8 * width}; shift > 0;) {
            shift -= 8;
            s << static_cast<uint8_t>(code >> shift);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        const size_t width{s.size()};
        if (width == 0 || width > sizeof(uint64_t)) {
            throw std::ios_base::failure("Invalid format for transaction index position");
        }
        uint64_t code{0};
        for (size_t i{0}; i < width; ++i) {
            uint8_t byte;
            s >> byte;
            code = (code << 8) | byte;
        }
        block_height = static_cast<uint32_t>(code / MAX_BLOCK_SERIALIZED_SIZE);
        tx_offset = static_cast<uint32_t>(code % MAX_BLOCK_SERIALIZED_SIZE);
    }
};

inline TxHashKeyPrefix CreateKeyPrefix(const PresaltedSipHasher& hasher, const uint256& tx_hash)
{
    const uint64_t siphash{hasher(tx_hash)};
    return TxHashKeyPrefix{
        static_cast<uint8_t>(siphash >> 0x38),
        static_cast<uint8_t>(siphash >> 0x30),
        static_cast<uint8_t>(siphash >> 0x28),
        static_cast<uint8_t>(siphash >> 0x20),
        static_cast<uint8_t>(siphash >> 0x18),
    };
}

template <typename TxHash>
inline TxHashKeyPrefix CreateKeyPrefix(const PresaltedSipHasher& hasher, const TxHash& tx_hash)
{
    return CreateKeyPrefix(hasher, tx_hash.ToUint256());
}

struct DBKey {
    TxHashKeyPrefix hash_prefix;
    Position pos;

    explicit DBKey(const TxHashKeyPrefix& hash_in, const Position& pos_in) : hash_prefix{hash_in}, pos{pos_in} {}

    SERIALIZE_METHODS(DBKey, obj)
    {
        uint8_t prefix{DB_TXINDEX_HASHED};
        READWRITE(prefix);
        if (prefix != DB_TXINDEX_HASHED) {
            throw std::ios_base::failure("Invalid format for transaction index DB key");
        }
        READWRITE(obj.hash_prefix);
        READWRITE(obj.pos);
    }
};
} // namespace txindex

#endif // BITCOIN_INDEX_TXINDEX_KEY_H

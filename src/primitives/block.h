// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>
#include <util/time.h>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // header
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint64_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
    //! Memory-only marker for the extended header encoding. This draft derives
    //! the value from a negative nVersion when parsing from the wire or disk.
    bool m_extended;

    static constexpr uint64_t EXTENDED_TIME_THRESHOLD{uint64_t{1} << 32};

    CBlockHeader()
    {
        SetNull();
    }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        const uint32_t time_low{static_cast<uint32_t>(nTime)};
        s << nVersion << hashPrevBlock << hashMerkleRoot;
        s << time_low;
        if (m_extended) {
            const uint32_t time_high{static_cast<uint32_t>(nTime >> 32)};
            s << time_high;
        }
        s << nBits << nNonce;
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        uint32_t time_low;
        s >> nVersion >> hashPrevBlock >> hashMerkleRoot;
        m_extended = nVersion < 0;
        s >> time_low;
        nTime = time_low;
        if (m_extended) {
            uint32_t time_high;
            s >> time_high;
            nTime |= uint64_t{time_high} << 32;
        }
        s >> nBits >> nNonce;
    }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        m_extended = false;
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const;

    void SetExtendedTimeEncoding()
    {
        m_extended = true;
        if (nVersion >= 0) {
            nVersion = nVersion == 0 ? -1 : -nVersion;
        }
    }

    void SetLegacyTimeEncoding()
    {
        m_extended = false;
    }

    NodeSeconds Time() const
    {
        return NodeSeconds{std::chrono::seconds{nTime}};
    }

    uint64_t GetBlockTime() const
    {
        return nTime;
    }
};


class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // Memory-only flags for caching expensive checks
    mutable bool fChecked;                            // CheckBlock()
    mutable bool m_checked_witness_commitment{false}; // CheckWitnessCommitment()
    mutable bool m_checked_merkle_root{false};        // CheckMerkleRoot()

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *(static_cast<CBlockHeader*>(this)) = header;
    }

    SERIALIZE_METHODS(CBlock, obj)
    {
        READWRITE(AsBase<CBlockHeader>(obj), obj.vtx);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
        m_checked_witness_commitment = false;
        m_checked_merkle_root = false;
    }

    std::string ToString() const;
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    /** Historically CBlockLocator's version field has been written to network
     * streams as the negotiated protocol version and to disk streams as the
     * client version, but the value has never been used.
     *
     * Hard-code to the highest protocol version ever written to a network stream.
     * SerParams can be used if the field requires any meaning in the future,
     **/
    static constexpr int DUMMY_VERSION = 70016;

    std::vector<uint256> vHave;

    CBlockLocator() = default;

    explicit CBlockLocator(std::vector<uint256>&& have) : vHave(std::move(have)) {}

    SERIALIZE_METHODS(CBlockLocator, obj)
    {
        int nVersion = DUMMY_VERSION;
        READWRITE(nVersion);
        READWRITE(obj.vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H

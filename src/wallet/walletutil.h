// Copyright (c) 2017-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_WALLETUTIL_H
#define BITCOIN_WALLET_WALLETUTIL_H

#include <script/descriptor.h>
#include <util/fs.h>

#include <vector>

namespace wallet {

enum WalletFlags : uint64_t {
    // wallet flags in the upper section (> 1 << 31) will lead to not opening the wallet if flag is unknown
    // unknown wallet flags in the lower section <= (1 << 31) will be tolerated

    // will categorize coins as clean (not reused) and dirty (reused), and handle
    // them with privacy considerations in mind
    WALLET_FLAG_AVOID_REUSE = (1ULL << 0),

    // Indicates that the metadata has already been upgraded to contain key origins
    WALLET_FLAG_KEY_ORIGIN_METADATA = (1ULL << 1),

    // Indicates that the descriptor cache has been upgraded to cache last hardened xpubs
    WALLET_FLAG_LAST_HARDENED_XPUB_CACHED = (1ULL << 2),

    // will enforce the rule that the wallet can't contain any private keys (only watch-only/pubkeys)
    WALLET_FLAG_DISABLE_PRIVATE_KEYS = (1ULL << 32),

    //! Flag set when a wallet contains no HD seed and no private keys, scripts,
    //! addresses, and other watch only things, and is therefore "blank."
    //!
    //! The main function this flag serves is to distinguish a blank wallet from
    //! a newly created wallet when the wallet database is loaded, to avoid
    //! initialization that should only happen on first run.
    //!
    //! A secondary function of this flag, which applies to descriptor wallets
    //! only, is to serve as an ongoing indication that descriptors in the
    //! wallet should be created manually, and that the wallet should not
    //! generate automatically generate new descriptors if it is later
    //! encrypted. To support this behavior, descriptor wallets unlike legacy
    //! wallets do not automatically unset the BLANK flag when things are
    //! imported.
    //!
    //! This flag is also a mandatory flag to prevent previous versions of
    //! bitcoin from opening the wallet, thinking it was newly created, and
    //! then improperly reinitializing it.
    WALLET_FLAG_BLANK_WALLET = (1ULL << 33),

    //! Indicate that this wallet supports DescriptorScriptPubKeyMan
    WALLET_FLAG_DESCRIPTORS = (1ULL << 34),

    //! Indicates that the wallet needs an external signer
    WALLET_FLAG_EXTERNAL_SIGNER = (1ULL << 35),

    //! Indicates that the wallet stores its descriptors in multipath form:
    //! each descriptor record is a BIP 389 multipath descriptor with exactly
    //! two derivation paths, covering both the receive and change chain, and
    //! the wallet only supports such descriptors. Mandatory so that previous
    //! versions, which can only load single path descriptor records, refuse
    //! to open the wallet.
    WALLET_FLAG_MULTIPATH_DESCRIPTORS = (1ULL << 36),
};

//! Get the path of the wallet directory.
fs::path GetWalletDir();

/** Descriptor with some wallet metadata */
class WalletDescriptor
{
public:
    //! Address generation state, kept per derivation path of a multipath descriptor
    struct PathState {
        int32_t next_index = 0; // Position of the next item to generate
        int32_t range_end = 0; // Item after the last; end of range, exclusive, i.e. [range_start, range_end). This will increment with each TopUp()
        DescriptorCache cache;
    };

private:
    int32_t range_start = 0; // First item in range; start of range, inclusive, i.e. [range_start, range_end). Shared by all paths and never changes.
    std::vector<PathState> m_paths{PathState{}}; // One entry per derivation path; size 1 for single path descriptors
public:
    std::shared_ptr<Descriptor> descriptor; // For a multipath descriptor, the expansion of the first path
    std::shared_ptr<MultipathDescriptor> multipath; // Set if this is a multipath descriptor
    uint256 id; // Descriptor ID (calculated once at descriptor initialization/deserialization)
    uint64_t creation_time = 0;

    bool IsMultipath() const { return multipath != nullptr; }
    size_t NumPaths() const { return m_paths.size(); }

    //! The descriptor expansion for the given derivation path
    const Descriptor& DescAt(size_t path = 0) const { return multipath ? *multipath->PathAt(path) : *descriptor; }

    DescriptorCache& CacheAt(size_t path = 0) { return m_paths.at(path).cache; }
    const DescriptorCache& CacheAt(size_t path = 0) const { return m_paths.at(path).cache; }

    int32_t GetStart() const { return range_start; }
    int32_t GetNext(size_t path = 0) const { return m_paths.at(path).next_index; }
    int32_t GetEnd(size_t path = 0) const { return m_paths.at(path).range_end; }

    //! Increments the next_index of the descriptor.
    void IncNext(size_t path = 0)
    {
        m_paths.at(path).next_index++;
    }

    //! Increments the next_index of the descriptor.
    void DecNext(size_t path = 0)
    {
        m_paths.at(path).next_index--;
    }

    //! Sets the range_end of the descriptor.
    void SetEnd(size_t path, int32_t end)
    {
        if (!descriptor->IsRange()) {
            CHECK_NONFATAL(end == 1);
        }
        m_paths.at(path).range_end = end;
    }

    void DeserializeDescriptor(const std::string& str)
    {
        std::string error;
        FlatSigningProvider keys;
        auto descs = Parse(str, keys, error, true);
        if (descs.empty()) {
            throw std::ios_base::failure("Invalid descriptor: " + error);
        }
        if (descs.size() > 1) {
            multipath = std::make_shared<MultipathDescriptor>(std::move(descs));
            descriptor = multipath->PathAt(0);
            id = DescriptorID(*multipath);
            m_paths.resize(multipath->PathCount());
        } else {
            descriptor = std::move(descs.at(0));
            id = DescriptorID(*descriptor);
            m_paths.resize(1);
        }
    }

    SERIALIZE_METHODS(WalletDescriptor, obj)
    {
        std::string descriptor_str;
        SER_WRITE(obj, descriptor_str = obj.multipath ? obj.multipath->ToString() : obj.descriptor->ToString());
        READWRITE(descriptor_str, obj.creation_time);
        // Parsing the descriptor determines the number of per-path states that follow.
        // The range start is shared by all paths and stored with the first one, so
        // for single path descriptors the resulting layout is unchanged from when
        // there was only a single such state.
        SER_READ(obj, obj.DeserializeDescriptor(descriptor_str));
        READWRITE(obj.m_paths.at(0).next_index, obj.range_start, obj.m_paths.at(0).range_end);
        for (size_t path = 1; path < obj.m_paths.size(); ++path) {
            READWRITE(obj.m_paths.at(path).next_index, obj.m_paths.at(path).range_end);
        }
    }

    WalletDescriptor() = default;
    WalletDescriptor(std::shared_ptr<Descriptor> descriptor, uint64_t creation_time, int32_t range_start, int32_t range_end, int32_t next_index)
    : range_start(descriptor->IsRange() ? range_start : 0),
      m_paths{{next_index,
               descriptor->IsRange() ? range_end : 1,
               DescriptorCache{}}},
      descriptor(descriptor),
      id(DescriptorID(*descriptor)),
      creation_time(creation_time) {}
    //! Multipath descriptor constructor; all paths start with the same range and next index.
    WalletDescriptor(std::shared_ptr<MultipathDescriptor> multipath, uint64_t creation_time, int32_t range_start, int32_t range_end, int32_t next_index)
    : range_start(multipath->PathAt(0)->IsRange() ? range_start : 0),
      m_paths(multipath->PathCount(),
              {next_index,
               multipath->PathAt(0)->IsRange() ? range_end : 1,
               DescriptorCache{}}),
      descriptor(multipath->PathAt(0)),
      multipath(multipath),
      id(DescriptorID(*multipath)),
      creation_time(creation_time) {}
};

WalletDescriptor GenerateWalletDescriptor(const CExtPubKey& master_key, const OutputType& output_type, bool internal);

} // namespace wallet

#endif // BITCOIN_WALLET_WALLETUTIL_H

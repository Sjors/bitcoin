// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/caches.h>

#include <common/args.h>
#include <kernel/caches.h>
#include <logging.h>
#include <util/byte_units.h>

#include <algorithm>
#include <string>

// Unlike for the UTXO database, for the txindex scenario the leveldb cache make
// a meaningful difference: https://github.com/bitcoin/bitcoin/pull/8273#issuecomment-229601991
//! Maximum dbcache size on 32-bit systems.
static constexpr size_t MAX_32BIT_DBCACHE{1024_MiB};

namespace node {
CacheSizes CalculateCacheSizes(const ArgsManager& args, size_t n_indexes)
{
    // Convert -dbcache from MiB units to bytes. The total cache is floored by MIN_DB_CACHE and capped by max size_t value.
    size_t total_cache{DEFAULT_DB_CACHE};
    if (std::optional<int64_t> db_cache = args.GetIntArg("-dbcache")) {
        if (*db_cache < 0) db_cache = 0;
        uint64_t db_cache_bytes = SaturatingLeftShift<uint64_t>(*db_cache, 20);
        constexpr auto max_db_cache{sizeof(void*) == 4 ? MAX_32BIT_DBCACHE : std::numeric_limits<size_t>::max()};
        total_cache = std::max<size_t>(MIN_DB_CACHE, std::min<uint64_t>(db_cache_bytes, max_db_cache));
    }

    IndexCacheSizes index_sizes;
    return {index_sizes, kernel::CacheSizes{total_cache}};
}
} // namespace node

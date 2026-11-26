// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_UTF8_H
#define BITCOIN_UTIL_UTF8_H

#include <cstddef>
#include <cstdint>
#include <span>

/** Validate UTF-8 as specified by RFC 3629, including empty strings and embedded NULs. */
inline bool IsValidUTF8(std::span<const uint8_t> text)
{
    for (size_t pos{0}; pos < text.size();) {
        const uint8_t first{text[pos++]};
        if (first < 0x80) continue;
        const size_t following{first >= 0xc2 && first <= 0xdf ? 1U :
                               first >= 0xe0 && first <= 0xef ? 2U :
                               first >= 0xf0 && first <= 0xf4 ? 3U : 0U};
        if (following == 0 || following > text.size() - pos) return false;
        // Exclude overlong encodings, surrogate code points, and values above U+10FFFF.
        if ((first == 0xe0 && text[pos] < 0xa0) || (first == 0xed && text[pos] >= 0xa0) ||
            (first == 0xf0 && text[pos] < 0x90) || (first == 0xf4 && text[pos] >= 0x90)) return false;
        for (size_t i{0}; i < following; ++i) {
            if ((text[pos++] & 0xc0) != 0x80) return false;
        }
    }
    return true;
}

#endif // BITCOIN_UTIL_UTF8_H

// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/strencodings.h>
#include <util/utf8.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

BOOST_AUTO_TEST_SUITE(utf8_tests)

BOOST_AUTO_TEST_CASE(valid_utf8)
{
    BOOST_CHECK(IsValidUTF8({}));
    std::array<uint8_t, 128> ascii;
    for (size_t i{0}; i < ascii.size(); ++i) ascii[i] = i;
    BOOST_CHECK(IsValidUTF8(ascii));

    std::vector<uint8_t> combined;
    for (const std::string hex : {"c280", "dfbf", "e0a080", "ed9fbf", "ee8080", "efbfbf", "efbbbf", "f0908080", "f48fbfbf"}) {
        BOOST_TEST_CONTEXT(hex) {
            const auto text{ParseHex(hex)};
            BOOST_CHECK(IsValidUTF8(text));
            // Every proper, nonempty prefix of a multibyte character is incomplete.
            for (size_t size{1}; size < text.size(); ++size) {
                BOOST_CHECK(!IsValidUTF8(std::span{text}.first(size)));
            }
            combined.insert(combined.end(), text.begin(), text.end());
            combined.push_back(0);
        }
    }
    BOOST_CHECK(IsValidUTF8(combined));
}

BOOST_AUTO_TEST_CASE(invalid_utf8)
{
    // Stray continuation bytes, overlong encodings, bad continuations,
    // surrogate code points, and encodings beyond U+10FFFF.
    for (const std::string hex : {"80", "bf", "c080", "c1bf", "c241", "e08080", "e228a1",
                                 "eda080", "edbfbf", "f0808080", "f0908041", "f4908080",
                                 "f5808080", "f888808080", "fc8480808080", "ff"}) {
        BOOST_TEST_CONTEXT(hex) {
            auto text{ParseHex(hex)};
            BOOST_CHECK(!IsValidUTF8(text));
            text.insert(text.begin(), 'a');
            text.push_back('z');
            BOOST_CHECK(!IsValidUTF8(text));
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()

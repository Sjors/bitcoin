// Copyright 2016 Wladimir J. van der Laan
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_UNIVALUE_INCLUDE_UNIVALUE_UTFFILTER_H
#define BITCOIN_UNIVALUE_INCLUDE_UNIVALUE_UTFFILTER_H

#include <span.h>
#include <util/utf8.h>

#include <string>

/**
 * Filter that generates and validates UTF-8, as well as collates UTF-16
 * surrogate pairs as specified in RFC4627.
 */
class JSONUTF8StringFilter
{
public:
    explicit JSONUTF8StringFilter(std::string& s)
        : str(s)
    {
    }
    // Write single 8-bit char (may be part of UTF-8 sequence)
    void push_back(unsigned char ch)
    {
        if (surpair) // A surrogate pair must consist of adjacent Unicode escapes.
            is_valid = false;
        // Preserve raw bytes so validation cannot normalize an invalid encoding.
        str.push_back(char(ch));
    }
    // Write codepoint directly, possibly collating surrogate pairs
    void push_back_u(unsigned int codepoint_)
    {
        if (codepoint_ >= 0xD800 && codepoint_ < 0xDC00) { // First half of surrogate pair
            if (surpair) // Two subsequent surrogate pair openers - fail
                is_valid = false;
            else
                surpair = codepoint_;
        } else if (codepoint_ >= 0xDC00 && codepoint_ < 0xE000) { // Second half of surrogate pair
            if (surpair) { // Open surrogate pair, expect second half
                // Compute code point from UTF-16 surrogate pair
                append_codepoint(0x10000 + ((surpair - 0xD800)<<10) + (codepoint_ - 0xDC00));
                surpair = 0;
            } else // Second half doesn't follow a first half - fail
                is_valid = false;
        } else {
            if (surpair) // First half of surrogate pair not followed by second - fail
                is_valid = false;
            else
                append_codepoint(codepoint_);
        }
    }
    // Check that we're in a state where the string can be ended
    // No open sequences, no open surrogate pairs, etc
    bool finalize()
    {
        if (surpair)
            is_valid = false;
        return is_valid && IsValidUTF8(MakeUCharSpan(str));
    }
private:
    std::string &str;
    bool is_valid{true};
    // Keep track of the following state to handle the following section of
    // RFC4627:
    //
    //    To escape an extended character that is not in the Basic Multilingual
    //    Plane, the character is represented as a twelve-character sequence,
    //    encoding the UTF-16 surrogate pair.  So, for example, a string
    //    containing only the G clef character (U+1D11E) may be represented as
    //    "\uD834\uDD1E".
    //
    //  Two subsequent \u.... may have to be replaced with one actual codepoint.
    unsigned int surpair{0}; // First half of open UTF-16 surrogate pair, or 0

    void append_codepoint(unsigned int codepoint_)
    {
        if (codepoint_ <= 0x7f)
            str.push_back((char)codepoint_);
        else if (codepoint_ <= 0x7FF) {
            str.push_back((char)(0xC0 | (codepoint_ >> 6)));
            str.push_back((char)(0x80 | (codepoint_ & 0x3F)));
        } else if (codepoint_ <= 0xFFFF) {
            str.push_back((char)(0xE0 | (codepoint_ >> 12)));
            str.push_back((char)(0x80 | ((codepoint_ >> 6) & 0x3F)));
            str.push_back((char)(0x80 | (codepoint_ & 0x3F)));
        } else if (codepoint_ <= 0x10FFFF) {
            str.push_back((char)(0xF0 | (codepoint_ >> 18)));
            str.push_back((char)(0x80 | ((codepoint_ >> 12) & 0x3F)));
            str.push_back((char)(0x80 | ((codepoint_ >> 6) & 0x3F)));
            str.push_back((char)(0x80 | (codepoint_ & 0x3F)));
        } else {
            is_valid = false;
        }
    }
};

#endif // BITCOIN_UNIVALUE_INCLUDE_UNIVALUE_UTFFILTER_H

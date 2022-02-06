// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <vector>
#include <script/script.h>
#include <script/miniscript.h>

#include <assert.h>

namespace miniscript {
namespace internal {

Type SanitizeType(Type e) {
    int num_types = (e << "K"_mst) + (e << "B"_mst);
    if (num_types == 0) return ""_mst; // No valid type, don't care about the rest
    assert(num_types == 1); // K, V, B all conflict with each other
    bool ok = // Work around a GCC 4.8 bug that breaks user-defined literals in macro calls.
        (!(e << "n"_mst) || !(e << "z"_mst)) && // n conflicts with z
        (!(e << "K"_mst) ||  (e << "u"_mst)) && // K implies u
        (!(e << "e"_mst) || !(e << "f"_mst)) && // e conflicts with f
        (!(e << "e"_mst) ||  (e << "d"_mst)) && // e implies d
        (!(e << "d"_mst) || !(e << "f"_mst)) && // d conflicts with f
        (!(e << "K"_mst) ||  (e << "s"_mst)); // K implies s
    assert(ok);
    return e;
}

Type ComputeType(NodeType nodetype, Type x, uint32_t k, size_t n_subs, size_t n_keys) {
    // Sanity check on k
    if (nodetype == NodeType::OLDER || nodetype == NodeType::AFTER) {
        assert(k >= 1 && k < 0x80000000UL);
    } else if (nodetype == NodeType::MULTI) {
        assert(k >= 1 && k <= n_keys);
    } else {
        assert(k == 0);
    }
    // Sanity check on subs
    if (nodetype == NodeType::WRAP_C) {
        assert(n_subs == 1);
    } else {
        assert(n_subs == 0);
    }
    // Sanity check on keys
    if (nodetype == NodeType::PK_K || nodetype == NodeType::PK_H) {
        assert(n_keys == 1);
    } else if (nodetype == NodeType::MULTI) {
        assert(n_keys >= 1 && n_keys <= 20);
    } else {
        assert(n_keys == 0);
    }

    // Below is the per-nodetype logic for computing the expression types.
    // It heavily relies on Type's << operator (where "X << a_mst" means
    // "X has all properties listed in a").
    switch (nodetype) {
        case NodeType::PK_K: return "Knudesk"_mst;
        case NodeType::PK_H: return "Knudesk"_mst;
        case NodeType::OLDER: return
            "g"_mst.If(k & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) |
            "h"_mst.If(!(k & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG)) |
            "Bzfk"_mst;
        case NodeType::AFTER: return
            "i"_mst.If(k >= LOCKTIME_THRESHOLD) |
            "j"_mst.If(k < LOCKTIME_THRESHOLD) |
            "Bzfk"_mst;
        case NodeType::WRAP_C: return
            "B"_mst.If(x << "K"_mst) | // B=K_x
            (x & "ghijk"_mst) | // g=g_x, h=h_x, i=i_x, j=j_x, k=k_x
            (x & "ndfe"_mst) | // n=n_x, d=d_x, f=f_x, e=e_x
            "us"_mst; // u, s
        case NodeType::MULTI: return "Bnudesk"_mst;
    }
    assert(false);
    return ""_mst;
}

size_t ComputeScriptLen(NodeType nodetype, Type sub0typ, size_t subsize, uint32_t k, size_t n_subs, size_t n_keys) {
    switch (nodetype) {
        case NodeType::PK_K: return subsize + 34;
        case NodeType::PK_H: return subsize + 3 + 21;
        case NodeType::OLDER: return subsize + 1 + (CScript() << k).size();
        case NodeType::AFTER: return subsize + 1 + (CScript() << k).size();
        case NodeType::WRAP_C: return subsize + 1;
        case NodeType::MULTI: return subsize + 3 + (n_keys > 16) + (k > 16) + 34 * n_keys;
    }
    assert(false);
    return 0;
}

int FindNextChar(Span<const char> sp, const char m)
{
    for (int i = 0; i < (int)sp.size(); ++i) {
        if (sp[i] == m) return i;
        // We only search within the current parentheses
        if (sp[i] == ')') break;
    }
    return -1;
}

} // namespace internal
} // namespace miniscript

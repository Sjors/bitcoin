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
    return e;
}

Type ComputeType(NodeType nodetype, Type x, size_t n_subs, size_t n_keys) {
    // Sanity check on subs
    if (nodetype == NodeType::WRAP_C) {
        assert(n_subs == 1);
    } else {
        assert(n_subs == 0);
    }
    // Sanity check on keys
    if (nodetype == NodeType::PK_H) {
        assert(n_keys == 1);
    } else {
        assert(n_keys == 0);
    }

    // Below is the per-nodetype logic for computing the expression types.
    // It heavily relies on Type's << operator (where "X << a_mst" means
    // "X has all properties listed in a").
    switch (nodetype) {
        case NodeType::PK_H: return "K"_mst;
        case NodeType::WRAP_C: return
            "B"_mst.If(x << "K"_mst); // B=K_x
    }
    assert(false);
    return ""_mst;
}

size_t ComputeScriptLen(NodeType nodetype, Type sub0typ, size_t subsize, size_t n_subs, size_t n_keys) {
    switch (nodetype) {
        case NodeType::PK_H: return subsize + 3 + 21;
        case NodeType::WRAP_C: return subsize + 1;
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

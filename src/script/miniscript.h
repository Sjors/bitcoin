// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_MINISCRIPT_H
#define BITCOIN_SCRIPT_MINISCRIPT_H

#include <algorithm>
#include <numeric>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <stdlib.h>
#include <assert.h>

#include <script/script.h>
#include <span.h>
#include <util/spanparsing.h>
#include <util/strencodings.h>
#include <util/vector.h>
#include <primitives/transaction.h>

namespace miniscript {

/** This type encapsulates the miniscript type system properties.
 *
 * Every miniscript expression is one of 4 basic types, and additionally has
 * a number of boolean type properties. More properties are added in later commits.
 *
 * The basic types are:
 * - "B" Base:
 *   - Takes its inputs from the top of the stack.
 *   - When satisfied, pushes a nonzero value of up to 4 bytes onto the stack.
 *   - When dissatisfied, pushes a 0 onto the stack.
 *   - This is used for most expressions, and required for the top level one.
 *   - For example: older(n) = <n> OP_CHECKSEQUENCEVERIFY.
 * - "V" Verify: introduced in a later commit
 * - "K" Key:
 *   - Takes its inputs from the top of the stack.
 *   - Becomes a B when followed by OP_CHECKSIG.
 *   - Always pushes a public key onto the stack, for which a signature is to be
 *     provided to satisfy the expression.
 *   - For example pk_h(key) = OP_DUP OP_HASH160 <Hash160(key)> OP_EQUALVERIFY
 * - "W" Wrapped: introduced in a later commit
 *
 * There a type properties that help reasoning about correctness:
 * - "z" Zero-arg:
 *   - Is known to always consume exactly 0 stack elements.
 *   - For example after(n) = <n> OP_CHECKLOCKTIMEVERIFY
 * - "n" Nonzero:
 *   - For every way this expression can be satisfied, a satisfaction exists that never needs
 *     a zero top stack element.
 *   - Conflicts with property 'z'
 * - "d" Dissatisfiable:
 *   - There is an easy way to construct a dissatisfaction for this expression.
 * - "u" Unit:
 *   - In case of satisfaction, an exact 1 is put on the stack (rather than just nonzero).
 *
 * Additional type properties help reasoning about nonmalleability:
 * - "e" Expression:
 *   - This implies property 'd', but the dissatisfaction is nonmalleable.
 *   - This generally requires 'e' for all subexpressions which are invoked for that
 *     dissatifsaction, and property 'f' for the unexecuted subexpressions in that case.
 * - "f" Forced:
 *   - Dissatisfactions (if any) for this expression always involve at least one signature.
 * - "s" Safe:
 *   - Satisfactions for this expression always involve at least one signature.
 *
 * Five more type properties for representing timelock information. Spend paths
 * in miniscripts containing conflicting timelocks and heightlocks cannot be spent together.
 * This helps users detect if miniscript does not match the semantic behaviour the
 * user expects.
 * - "g" Whether the branch contains a relative time timelock
 * - "h" Whether the branch contains a relative height timelock
 * - "i" Whether the branch contains a absolute time timelock
 * - "j" Whether the branch contains a absolute time heightlock
 * - "k"
 *   - Whether all satisfactions of this expression don't contain a mix of heightlock and timelock
 *     of the same type.
 *   - If the miniscript does not have the "k" property, the miniscript template will not match
 *     the user expectation of the corresponding spending policy.
 * For each of these properties the subset rule holds: an expression with properties X, Y, and Z, is also
 * valid in places where an X, a Y, a Z, an XY, ... is expected.
*/
class Type {
    //! Internal bitmap of properties (see ""_mst operator for details).
    uint32_t m_flags;

    //! Internal constructor used by the ""_mst operator.
    explicit constexpr Type(uint32_t flags) : m_flags(flags) {}

public:
    //! The only way to publicly construct a Type is using this literal operator.
    friend constexpr Type operator"" _mst(const char* c, size_t l);

    //! Compute the type with the union of properties.
    constexpr Type operator|(Type x) const { return Type(m_flags | x.m_flags); }

    //! Compute the type with the intersection of properties.
    constexpr Type operator&(Type x) const { return Type(m_flags & x.m_flags); }

    //! Check whether the left hand's properties are superset of the right's (= left is a subtype of right).
    constexpr bool operator<<(Type x) const { return (x.m_flags & ~m_flags) == 0; }

    //! Comparison operator to enable use in sets/maps (total ordering incompatible with <<).
    constexpr bool operator<(Type x) const { return m_flags < x.m_flags; }

    //! Equality operator.
    constexpr bool operator==(Type x) const { return m_flags == x.m_flags; }

    //! The empty type if x is false, itself otherwise.
    constexpr Type If(bool x) const { return Type(x ? m_flags : 0); }
};

//! Literal operator to construct Type objects.
inline constexpr Type operator"" _mst(const char* c, size_t l) {
    return l == 0 ? Type(0) : operator"" _mst(c + 1, l - 1) | Type(
        *c == 'B' ? 1 << 0 : // Base type
        *c == 'K' ? 1 << 2 : // Key type
        *c == 'z' ? 1 << 4 : // Zero-arg property
        *c == 'n' ? 1 << 6 : // Nonzero arg property
        *c == 'd' ? 1 << 7 : // Dissatisfiable property
        *c == 'u' ? 1 << 8 : // Unit property
        *c == 'e' ? 1 << 9 : // Expression property
        *c == 'f' ? 1 << 10 : // Forced property
        *c == 's' ? 1 << 11 : // Safe property
        *c == 'g' ? 1 << 14 : // older: contains relative time timelock   (csv_time)
        *c == 'h' ? 1 << 15 : // older: contains relative height timelock (csv_height)
        *c == 'i' ? 1 << 16 : // after: contains time timelock   (cltv_time)
        *c == 'j' ? 1 << 17 : // after: contains height timelock   (cltv_height)
        *c == 'k' ? 1 << 18 : // does not contain a combination of height and time locks
        (throw std::logic_error("Unknown character in _mst literal"), 0)
    );
}

template<typename Key> struct Node;
template<typename Key> using NodeRef = std::shared_ptr<const Node<Key>>;

//! Construct a miniscript node as a shared_ptr.
template<typename Key, typename... Args>
NodeRef<Key> MakeNodeRef(Args&&... args) { return std::make_shared<const Node<Key>>(std::forward<Args>(args)...); }

//! The different node types in miniscript.
enum class NodeType {
    JUST_0,    //!< OP_0
    JUST_1,    //!< OP_1
    PK_K,      //!< [key]
    PK_H,      //!< OP_DUP OP_HASH160 [keyhash] OP_EQUALVERIFY
    OLDER,     //!< [n] OP_CHECKSEQUENCEVERIFY
    AFTER,     //!< [n] OP_CHECKLOCKTIMEVERIFY
    WRAP_C,    //!< [X] OP_CHECKSIG
    MULTI,     //!< [k] [key_n]* [n] OP_CHECKMULTISIG
};

namespace internal {

//! Helper function for Node::CalcType.
Type ComputeType(NodeType nodetype, Type x, uint32_t k, size_t n_subs, size_t n_keys);

//! Helper function for Node::CalcScriptLen.
size_t ComputeScriptLen(NodeType nodetype, Type sub0typ, size_t subsize, uint32_t k, size_t n_subs, size_t n_keys);

//! A helper sanitizer/checker for the output of CalcType.
Type SanitizeType(Type x);

} // namespace internal

//! A node in a miniscript expression.
template<typename Key>
struct Node {
    //! What node type this node is.
    const NodeType nodetype;
    //! The k parameter (time for OLDER/AFTER, threshold for MULTI)
    const uint32_t k = 0;
    //! The keys used by this expression (only for PK_K/PK_H/MULTI)
    const std::vector<Key> keys;
    //! Subexpressions (for WRAP_C)
    const std::vector<NodeRef<Key>> subs;

private:
    //! Cached expression type (computed by CalcType and fed through SanitizeType).
    const Type typ;
    //! Cached script length (computed by CalcScriptLen).
    const size_t scriptlen;

    //! Compute the length of the script for this miniscript (including children).
    size_t CalcScriptLen() const {
        size_t subsize = 0;
        for (const auto& sub : subs) {
            subsize += sub->ScriptSize();
        }
        Type sub0type = subs.size() > 0 ? subs[0]->GetType() : ""_mst;
        return internal::ComputeScriptLen(nodetype, sub0type, subsize, k, subs.size(), keys.size());
    }

    /* Apply a recursive algorithm to a Miniscript tree, without actual recursive calls.
     *
     * The algorithm is defined by two functions: downfn and upfn. Conceptually, the
     * result can be thought of as first using downfn to compute a "state" for each node,
     * from the root down to the leaves. Then upfn is used to compute a "result" for each
     * node, from the leaves back up to the root, which is then returned. In the actual
     * implementation, both functions are invoked in an interleaved fashion, performing a
     * depth-first traversal of the tree.
     *
     * In more detail, it is invoked as node.TreeEvalMaybe<Result>(root, downfn, upfn):
     * - root is the state of the root node, of type State.
     * - downfn is a callable (State&, const Node&, size_t) -> State, which given a
     *   node, its state, and an index of one of its children, computes the state of that
     *   child. It can modify the state. Children of a given node will have downfn()
     *   called in order.
     * - upfn is a callable (State&&, const Node&, Span<Result>) -> std::optional<Result>,
     *   which given a node, its state, and a Span of the results of its children,
     *   computes the result of the node. If std::nullopt is returned by upfn,
     *   TreeEvalMaybe() immediately returns std::nullopt.
     * The return value of TreeEvalMaybe is the result of the root node.
     */
    template<typename Result, typename State, typename DownFn, typename UpFn>
    std::optional<Result> TreeEvalMaybe(State root_state, DownFn downfn, UpFn upfn) const
    {
        /** Entries of the explicit stack tracked in this algorithm. */
        struct StackElem
        {
            const Node& node; //!< The node being evaluated.
            size_t expanded; //!< How many children of this node have been expanded.
            State state; //!< The state for that node.

            StackElem(const Node& node_, size_t exp_, State&& state_) :
                node(node_), expanded(exp_), state(std::move(state_)) {}
        };
        /* Stack of tree nodes being explored. */
        std::vector<StackElem> stack;
        /* Results of subtrees so far. Their order and mapping to tree nodes
         * is implicitly defined by stack. */
        std::vector<Result> results;
        stack.emplace_back(*this, 0, std::move(root_state));

        /* Here is a demonstration of the algorithm, for an example tree A(B,C(D,E),F).
         * State variables are omitted for simplicity.
         *
         * First: stack=[(A,0)] results=[]
         *        stack=[(A,1),(B,0)] results=[]
         *        stack=[(A,1)] results=[B]
         *        stack=[(A,2),(C,0)] results=[B]
         *        stack=[(A,2),(C,1),(D,0)] results=[B]
         *        stack=[(A,2),(C,1)] results=[B,D]
         *        stack=[(A,2),(C,2),(E,0)] results=[B,D]
         *        stack=[(A,2),(C,2)] results=[B,D,E]
         *        stack=[(A,2)] results=[B,C]
         *        stack=[(A,3),(F,0)] results=[B,C]
         *        stack=[(A,3)] results=[B,C,F]
         * Final: stack=[] results=[A]
         */
        while (stack.size()) {
            const Node& node = stack.back().node;
            if (stack.back().expanded < node.subs.size()) {
                /* We encounter a tree node with at least one unexpanded child.
                 * Expand it. By the time we hit this node again, the result of
                 * that child (and all earlier children) will be on the stack. */
                size_t child_index = stack.back().expanded++;
                State child_state = downfn(stack.back().state, node, child_index);
                stack.emplace_back(*node.subs[child_index], 0, std::move(child_state));
                continue;
            }
            // Invoke upfn with the last node.subs.size() elements of results as input.
            assert(results.size() >= node.subs.size());
            std::optional<Result> result{upfn(std::move(stack.back().state), node,
                Span<Result>{results}.last(node.subs.size()))};
            // If evaluation returns std::nullopt, abort immediately.
            if (!result) return {};
            // Replace the last node.subs.size() elements of results with the new result.
            results.erase(results.end() - node.subs.size(), results.end());
            results.push_back(std::move(*result));
            stack.pop_back();
        }
        // The final remaining results element is the root result, return it.
        assert(results.size() == 1);
        return std::move(results[0]);
    }

    /** Like TreeEvalMaybe, but always produces a result. upfn must return Result. */
    template<typename Result, typename State, typename DownFn, typename UpFn>
    Result TreeEval(State root_state, DownFn&& downfn, UpFn upfn) const
    {
        // Invoke TreeEvalMaybe with upfn wrapped to return std::optional<Result>, and then
        // unconditionally dereference the result (it cannot be std::nullopt).
        return std::move(*TreeEvalMaybe<Result>(std::move(root_state),
            std::forward<DownFn>(downfn),
            [&upfn](State&& state, const Node& node, Span<Result> subs) {
                Result res{upfn(std::move(state), node, subs)};
                return std::optional<Result>(std::move(res));
            }
        ));
    }

    //! Compute the type for this miniscript.
    Type CalcType() const {
        using namespace internal;

        // All nodes can be computed just from the types of the 0-1 subexpexpressions.
        Type x = subs.size() > 0 ? subs[0]->GetType() : ""_mst;

        return SanitizeType(ComputeType(nodetype, x, k, subs.size(), keys.size()));
    }

public:
    template<typename Ctx>
    CScript ToScript(const Ctx& ctx) const
    {
        // To construct the CScript for a Miniscript object, we use the TreeEval algorithm.
        // The State is a boolean: whether or not the node's script expansion is followed
        // by an OP_VERIFY (which may need to be combined with the last script opcode).
        auto downfn = [](bool verify, const Node& node, size_t index) {
            return false;
        };
        // The upward function computes for a node, given its followed-by-OP_VERIFY status
        // and the CScripts of its child nodes, the CScript of the node.
        auto upfn = [&ctx](bool verify, const Node& node, Span<CScript> subs) -> CScript {
            switch (node.nodetype) {
                case NodeType::PK_K: return CScript() << ctx.ToPKBytes(node.keys[0]);
                case NodeType::PK_H: return CScript() << OP_DUP << OP_HASH160 << ctx.ToPKHBytes(node.keys[0]) << OP_EQUALVERIFY;
                case NodeType::OLDER: return CScript() << node.k << OP_CHECKSEQUENCEVERIFY;
                case NodeType::AFTER: return CScript() << node.k << OP_CHECKLOCKTIMEVERIFY;
                case NodeType::WRAP_C: return std::move(subs[0]) + CScript() << (verify ? OP_CHECKSIGVERIFY : OP_CHECKSIG);
                case NodeType::JUST_1: return CScript() << OP_1;
                case NodeType::JUST_0: return CScript() << OP_0;
                case NodeType::MULTI: {
                    CScript script = CScript() << node.k;
                    for (const auto& key : node.keys) {
                        script << ctx.ToPKBytes(key);
                    }
                    return std::move(script) << node.keys.size() << (verify ? OP_CHECKMULTISIGVERIFY : OP_CHECKMULTISIG);
                }
            }
            assert(false);
            return {};
        };
        return TreeEval<CScript>(false, downfn, upfn);
    }

    template<typename CTx>
    bool ToString(const CTx& ctx, std::string& ret) const {
        // To construct the std::string representation for a Miniscript object, we use
        // the TreeEvalMaybe algorithm. The State is a boolean: whether the parent node is a
        // wrapper. If so, non-wrapper expressions must be prefixed with a ":".
        auto downfn = [](bool, const Node& node, size_t) {
            return node.nodetype == NodeType::WRAP_C;
        };
        // The upward function computes for a node, given whether its parent is a wrapper,
        // and the string representations of its child nodes, the string representation of the node.
        auto upfn = [&ctx](bool wrapped, const Node& node, Span<std::string> subs) -> std::optional<std::string> {
            std::string ret = wrapped ? ":" : "";

            switch (node.nodetype) {
                case NodeType::WRAP_C:
                    if (node.subs[0]->nodetype == NodeType::PK_K) {
                        // pk(K) is syntactic sugar for c:pk_k(K)
                        std::string key_str;
                        if (!ctx.ToString(node.subs[0]->keys[0], key_str)) return {};
                        return std::move(ret) + "pk(" + std::move(key_str) + ")";
                    }
                    if (node.subs[0]->nodetype == NodeType::PK_H) {
                        // pkh(K) is syntactic sugar for c:pk_h(K)
                        std::string key_str;
                        if (!ctx.ToString(node.subs[0]->keys[0], key_str)) return {};
                        return std::move(ret) + "pkh(" + std::move(key_str) + ")";
                    }
                    return "c" + std::move(subs[0]);
                default: break;
            }
            switch (node.nodetype) {
                case NodeType::PK_K: {
                    std::string key_str;
                    if (!ctx.ToString(node.keys[0], key_str)) return {};
                    return std::move(ret) + "pk_k(" + std::move(key_str) + ")";
                }
                case NodeType::PK_H: {
                    std::string key_str;
                    if (!ctx.ToString(node.keys[0], key_str)) return {};
                    return std::move(ret) + "pk_h(" + std::move(key_str) + ")";
                }
                case NodeType::AFTER: return std::move(ret) + "after(" + ::ToString(node.k) + ")";
                case NodeType::OLDER: return std::move(ret) + "older(" + ::ToString(node.k) + ")";
                case NodeType::JUST_1: return std::move(ret) + "1";
                case NodeType::JUST_0: return std::move(ret) + "0";
                case NodeType::MULTI: {
                    auto str = std::move(ret) + "multi(" + ::ToString(node.k);
                    for (const auto& key : node.keys) {
                        std::string key_str;
                        if (!ctx.ToString(key, key_str)) return {};
                        str += "," + std::move(key_str);
                    }
                    return std::move(str) + ")";
                }
                default: assert(false);
            }
            return ""; // Should never be reached.
        };

        auto res = TreeEvalMaybe<std::string>(false, downfn, upfn);
        if (res.has_value()) ret = std::move(*res);
        return res.has_value();
    }

public:
    //! Return the size of the script for this expression (faster than ToScript().size()).
    size_t ScriptSize() const { return scriptlen; }

    //! Return the expression type.
    Type GetType() const { return typ; }

    //! Check whether this node is valid at all.
    bool IsValid() const { return !(GetType() == ""_mst); }

    //! Check whether this node is valid as a script on its own.
    bool IsValidTopLevel() const { return GetType() << "B"_mst; }

    //! Check whether this script always needs a signature.
    bool NeedsSignature() const { return GetType() << "s"_mst; }

    //! Do all sanity checks.
    bool IsSane() const { return GetType() << "k"_mst && IsValid(); }

    //! Check whether this node is safe as a script on its own.
    bool IsSaneTopLevel() const { return IsValidTopLevel() && IsSane() && NeedsSignature(); }

    //! Equality testing.
    bool operator==(const Node<Key>& arg) const
    {
        if (nodetype != arg.nodetype) return false;
        if (k != arg.k) return false;
        if (keys != arg.keys) return false;
        if (subs.size() != arg.subs.size()) return false;
        for (size_t i = 0; i < subs.size(); ++i) {
            if (!(*subs[i] == *arg.subs[i])) return false;
        }
        assert(scriptlen == arg.scriptlen);
        assert(typ == arg.typ);
        return true;
    }

    // Constructors with various argument combinations.
    Node(NodeType nt, std::vector<NodeRef<Key>> sub, std::vector<unsigned char> arg, uint32_t val = 0) : nodetype(nt), k(val), subs(std::move(sub)), typ(CalcType()), scriptlen(CalcScriptLen()) {}
    Node(NodeType nt, std::vector<unsigned char> arg, uint32_t val = 0) : nodetype(nt), k(val), typ(CalcType()), scriptlen(CalcScriptLen()) {}
    Node(NodeType nt, std::vector<NodeRef<Key>> sub, std::vector<Key> key, uint32_t val = 0) : nodetype(nt), k(val), keys(std::move(key)), subs(std::move(sub)), typ(CalcType()), scriptlen(CalcScriptLen()) {}
    Node(NodeType nt, std::vector<Key> key, uint32_t val = 0) : nodetype(nt), k(val), keys(std::move(key)), typ(CalcType()), scriptlen(CalcScriptLen()) {}
    Node(NodeType nt, std::vector<NodeRef<Key>> sub, uint32_t val = 0) : nodetype(nt), k(val), subs(std::move(sub)), typ(CalcType()), scriptlen(CalcScriptLen()) {}
    Node(NodeType nt, uint32_t val = 0) : nodetype(nt), k(val), typ(CalcType()), scriptlen(CalcScriptLen()) {}
};

namespace internal {

enum class ParseContext {
    /** An expression which may be begin with wrappers followed by a colon. */
    WRAPPED_EXPR,
    /** A miniscript expression which does not begin with wrappers. */
    EXPR,

    /** CHECK wraps the top constructed node with c: */
    CHECK,

    /** COMMA expects the next element to be ',' and fails if not. */
    COMMA,
    /** CLOSE_BRACKET expects the next element to be ')' and fails if not. */
    CLOSE_BRACKET,
};


int FindNextChar(Span<const char> in, const char m);

/** BuildBack pops the last two elements off `constructed` and wraps them in the specified NodeType */
template<typename Key>
void BuildBack(NodeType nt, std::vector<NodeRef<Key>>& constructed, const bool reverse = false)
{
    NodeRef<Key> child = std::move(constructed.back());
    constructed.pop_back();
    if (reverse) {
        constructed.back() = MakeNodeRef<Key>(nt, Vector(std::move(child), std::move(constructed.back())));
    } else {
        constructed.back() = MakeNodeRef<Key>(nt, Vector(std::move(constructed.back()), std::move(child)));
    }
}

//! Parse a miniscript from its textual descriptor form.
template<typename Key, typename Ctx>
inline NodeRef<Key> Parse(Span<const char> in, const Ctx& ctx)
{
    using namespace spanparsing;

    std::vector<std::tuple<ParseContext, int64_t>> to_parse;
    std::vector<NodeRef<Key>> constructed;

    to_parse.emplace_back(ParseContext::WRAPPED_EXPR, -1);

    while (!to_parse.empty()) {
        int64_t k = -1; // multi() threshold
        // Get the current context we are decoding within
        auto [cur_context, n] = to_parse.back();
        to_parse.pop_back();

        switch (cur_context) {
        case ParseContext::WRAPPED_EXPR: {
            int colon_index = -1;
            for (int i = 1; i < (int)in.size(); ++i) {
                if (in[i] == ':') {
                    colon_index = i;
                    break;
                }
                if (in[i] < 'a' || in[i] > 'z') break;
            }
            // If there is no colon, this loop won't execute
            for (int j = 0; j < colon_index; ++j) {
                if (in[j] == 'c') {
                    to_parse.emplace_back(ParseContext::CHECK, -1);
                } else {
                    return {};
                }
            }
            to_parse.emplace_back(ParseContext::EXPR, -1);
            in = in.subspan(colon_index + 1);
            break;
        }
        case ParseContext::EXPR: {
            if (Const("0", in)) {
                constructed.push_back(MakeNodeRef<Key>(NodeType::JUST_0));
            } else if (Const("1", in)) {
                constructed.push_back(MakeNodeRef<Key>(NodeType::JUST_1));
            } else if (Const("pk(", in)) {
                Key key;
                int key_size = FindNextChar(in, ')');
                if (key_size < 1) return {};
                if (!ctx.FromString(in.begin(), in.begin() + key_size, key)) return {};
                constructed.push_back(MakeNodeRef<Key>(NodeType::WRAP_C, Vector(MakeNodeRef<Key>(NodeType::PK_K, Vector(std::move(key))))));
                in = in.subspan(key_size + 1);
            } else if (Const("pkh(", in)) {
                Key key;
                int key_size = FindNextChar(in, ')');
                if (key_size < 1) return {};
                if (!ctx.FromString(in.begin(), in.begin() + key_size, key)) return {};
                constructed.push_back(MakeNodeRef<Key>(NodeType::WRAP_C, Vector(MakeNodeRef<Key>(NodeType::PK_H, Vector(std::move(key))))));
                in = in.subspan(key_size + 1);
            } else if (Const("pk_k(", in)) {
                Key key;
                int key_size = FindNextChar(in, ')');
                if (key_size < 1) return {};
                if (!ctx.FromString(in.begin(), in.begin() + key_size, key)) return {};
                constructed.push_back(MakeNodeRef<Key>(NodeType::PK_K, Vector(std::move(key))));
                in = in.subspan(key_size + 1);
            } else if (Const("pk_h(", in)) {
                Key key;
                int key_size = FindNextChar(in, ')');
                if (key_size < 1) return {};
                if (!ctx.FromString(in.begin(), in.begin() + key_size, key)) return {};
                constructed.push_back(MakeNodeRef<Key>(NodeType::PK_H, Vector(std::move(key))));
                in = in.subspan(key_size + 1);
            } else if (Const("after(", in)) {
                int arg_size = FindNextChar(in, ')');
                if (arg_size < 1) return {};
                int64_t num;
                if (!ParseInt64(std::string(in.begin(), in.begin() + arg_size), &num)) return {};
                if (num < 1 || num >= 0x80000000L) return {};
                constructed.push_back(MakeNodeRef<Key>(NodeType::AFTER, num));
                in = in.subspan(arg_size + 1);
            } else if (Const("older(", in)) {
                int arg_size = FindNextChar(in, ')');
                if (arg_size < 1) return {};
                int64_t num;
                if (!ParseInt64(std::string(in.begin(), in.begin() + arg_size), &num)) return {};
                if (num < 1 || num >= 0x80000000L) return {};
                constructed.push_back(MakeNodeRef<Key>(NodeType::OLDER, num));
                in = in.subspan(arg_size + 1);
            } else if (Const("multi(", in)) {
                // Get threshold
                int next_comma = FindNextChar(in, ',');
                if (next_comma < 1) return {};
                if (!ParseInt64(std::string(in.begin(), in.begin() + next_comma), &k)) return {};
                in = in.subspan(next_comma + 1);
                // Get keys
                std::vector<Key> keys;
                while (next_comma != -1) {
                    Key key;
                    next_comma = FindNextChar(in, ',');
                    int key_length = (next_comma == -1) ? FindNextChar(in, ')') : next_comma;
                    if (key_length < 1) return {};
                    if (!ctx.FromString(in.begin(), in.begin() + key_length, key)) return {};
                    keys.push_back(std::move(key));
                    in = in.subspan(key_length + 1);
                }
                if (keys.size() < 1 || keys.size() > 20) return {};
                if (k < 1 || k > (int64_t)keys.size()) return {};
                constructed.push_back(MakeNodeRef<Key>(NodeType::MULTI, std::move(keys), k));
            }
            break;
        }
        case ParseContext::CHECK: {
            constructed.back() = MakeNodeRef<Key>(NodeType::WRAP_C, Vector(std::move(constructed.back())));
            break;
        }
        case ParseContext::COMMA: {
            if (in.size() < 1 || in[0] != ',') return {};
            in = in.subspan(1);
            break;
        }
        case ParseContext::CLOSE_BRACKET: {
            if (in.size() < 1 || in[0] != ')') return {};
            in = in.subspan(1);
            break;
        }
        }
    }

    // Sanity checks on the produced miniscript
    assert(constructed.size() == 1);
    if (in.size() > 0) return {};
    const NodeRef<Key> tl_node = std::move(constructed.front());
    if (!tl_node->IsValidTopLevel()) return {};
    return tl_node;
}

} // namespace internal

template<typename Ctx>
inline NodeRef<typename Ctx::Key> FromString(const std::string& str, const Ctx& ctx) {
    return internal::Parse<typename Ctx::Key>(str, ctx);
}

} // namespace miniscript

#endif // BITCOIN_SCRIPT_MINISCRIPT_H

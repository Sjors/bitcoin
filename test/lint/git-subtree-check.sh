#!/bin/sh
# Copyright (c) 2015-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# The default check (no flags) verifies that the subtree directory has not
# been touched outside of a subtree merge. With -r, it additionally verifies
# that the recorded subtree commit exists in the local repository and that
# its tree matches what is checked in (assumes the upstream remote has been
# fetched).
#
# With -s, for subtrees imported from a 'git subtree split' branch (rather
# than upstream master directly), it re-runs the deterministic split locally
# on FETCH_HEAD and confirms the recorded subtree commit is reachable from
# the result. This catches the case where a malicious upstream publishes a
# split branch with contents that don't match what 'git subtree split' would
# produce from master. 'git subtree split' is deterministic and incremental,
# so re-runs are cheap (cached under refs/subtree-cache/) and any honest
# split SHA from past upstream history will still be reachable from a fresh
# split of current master.

export LC_ALL=C

check_remote=0
split_prefix=
while getopts "?hrs:" opt; do
  case $opt in
    '?' | h)
      echo "Usage: $0 [-r] [-s SPLIT_PREFIX] DIR [COMMIT]"
      echo "       $0 -?"
      echo ""
      echo "Checks that a certain prefix is pure subtree, and optionally whether the"
      echo "referenced commit is present in any fetched remote."
      echo ""
      echo "DIR is the prefix within the repository to check."
      echo "COMMIT is the commit to check, if it is not provided, HEAD will be used."
      echo ""
      echo "-r      Check that subtree commit is present in repository."
      echo "        To do this check, fetch the subtreed remote first. Example:"
      echo ""
      echo "            git fetch https://github.com/bitcoin-core/secp256k1.git"
      echo "            test/lint/git-subtree-check.sh -r src/secp256k1"
      echo ""
      echo "-s SPLIT_PREFIX"
      echo "        For subtrees imported from a 'git subtree split' branch (rather"
      echo "        than from upstream master directly), verify that the recorded"
      echo "        subtree commit could have been produced by"
      echo "        'git subtree split --prefix=SPLIT_PREFIX' from upstream master."
      echo "        Implies -r. Requires upstream master to have been fetched into"
      echo "        FETCH_HEAD immediately before running this script. Example:"
      echo ""
      echo "            git fetch https://github.com/example/foo.git master"
      echo "            test/lint/git-subtree-check.sh -s lib src/foo"
      exit 1
    ;;
    r)
      check_remote=1
    ;;
    s)
      split_prefix="${OPTARG%/}"
      check_remote=1
    ;;
  esac
done
shift $((OPTIND-1))

if [ -z "$1" ]; then
    echo "Need to provide a DIR, see $0 -?"
    exit 1
fi

# Strip trailing / from directory path (in case it was added by autocomplete)
DIR="${1%/}"
COMMIT="$2"
if [ -z "$COMMIT" ]; then
    COMMIT=HEAD
fi

# Taken from git-subtree (Copyright (C) 2009 Avery Pennarun <apenwarr@gmail.com>)
find_latest_squash()
{
    dir="$1"
    sq=
    main=
    sub=
    git log --grep="^git-subtree-dir: $dir/*\$" \
        --pretty=format:'START %H%n%s%n%n%b%nEND%n' "$COMMIT" |
    while read a b _; do
        case "$a" in
            START) sq="$b" ;;
            git-subtree-mainline:) main="$b" ;;
            git-subtree-split:) sub="$b" ;;
            END)
                if [ -n "$sub" ]; then
                    if [ -n "$main" ]; then
                        # a rejoin commit?
                        # Pretend its sub was a squash.
                        sq="$sub"
                    fi
                    echo "$sq" "$sub"
                    break
                fi
                sq=
                main=
                sub=
                ;;
        esac
    done
}

# find latest subtree update
latest_squash="$(find_latest_squash "$DIR")"
if [ -z "$latest_squash" ]; then
    echo "ERROR: $DIR is not a subtree" >&2
    exit 2
fi
# shellcheck disable=SC2086
set $latest_squash
old=$1
rev=$2

# get the tree in the current commit
tree_actual=$(git ls-tree -d "$COMMIT" "$DIR" | head -n 1)
if [ -z "$tree_actual" ]; then
    echo "FAIL: subtree directory $DIR not found in $COMMIT" >&2
    exit 1
fi
# shellcheck disable=SC2086
set $tree_actual
tree_actual_type=$2
tree_actual_tree=$3
echo "$DIR in $COMMIT currently refers to $tree_actual_type $tree_actual_tree"
if [ "d$tree_actual_type" != "dtree" ]; then
    echo "FAIL: subtree directory $DIR is not a tree in $COMMIT" >&2
    exit 1
fi

# get the tree at the time of the last subtree update
tree_commit=$(git show -s --format="%T" "$old")
echo "$DIR in $COMMIT was last updated in commit $old (tree $tree_commit)"

# ... and compare the actual tree with it
if [ "$tree_actual_tree" != "$tree_commit" ]; then
    git diff "$tree_commit" "$tree_actual_tree" >&2
    echo "FAIL: subtree directory was touched without subtree merge" >&2
    exit 1
fi

if [ "$check_remote" != "0" ]; then
    # get the tree in the subtree commit referred to
    if [ "d$(git cat-file -t "$rev" 2>/dev/null)" != dcommit ]; then
        echo "subtree commit $rev unavailable: cannot compare. Did you add and fetch the remote?" >&2
        exit 1
    fi
    tree_subtree=$(git show -s --format="%T" "$rev")
    echo "$DIR in $COMMIT was last updated to upstream commit $rev (tree $tree_subtree)"

    # ... and compare the actual tree with it
    if [ "$tree_actual_tree" != "$tree_subtree" ]; then
        echo "FAIL: subtree update commit differs from upstream tree!" >&2
        exit 1
    fi
fi

if [ -n "$split_prefix" ]; then
    # See header comment for rationale. $rev is the subtree commit recorded
    # in the latest squash; check that it is reachable from a fresh local
    # split of upstream FETCH_HEAD at $split_prefix.
    if [ "d$(git cat-file -t FETCH_HEAD 2>/dev/null)" != dcommit ]; then
        echo "FETCH_HEAD unavailable: cannot verify split. Did you fetch upstream master?" >&2
        exit 1
    fi
    upstream_commit=$(git rev-parse --verify "FETCH_HEAD^{commit}")
    echo "verifying $rev was produced by 'git subtree split --prefix=$split_prefix' from FETCH_HEAD ($upstream_commit)"

    if ! split_head=$(
        repo_root=$(pwd)
        split_worktree=$(mktemp -d "${TMPDIR:-/tmp}/git-subtree-check.XXXXXX") || exit 1
        trap 'git -c safe.directory="$repo_root" worktree remove --force "$split_worktree" >/dev/null 2>&1 || rm -rf "$split_worktree"' EXIT HUP INT TERM

        # git-subtree before 2.54 (commit a606fcdceb) required --prefix to
        # exist in the current worktree, even when splitting a different
        # revision. Run the split inside a detached worktree at FETCH_HEAD so
        # the prefix is always present regardless of the local git version.
        git -c safe.directory="$repo_root" worktree add --quiet --detach "$split_worktree" "$upstream_commit" >/dev/null 2>&1 || exit 1
        git -c safe.directory="$repo_root" -c safe.directory="$split_worktree" -C "$split_worktree" subtree split --prefix="$split_prefix" HEAD 2>/dev/null
    ); then
        echo "FAIL: 'git subtree split --prefix=$split_prefix FETCH_HEAD' failed (does the prefix exist in FETCH_HEAD?)" >&2
        exit 1
    fi

    if ! git merge-base --is-ancestor "$rev" "$split_head"; then
        echo "FAIL: subtree commit $rev is not reachable from 'git subtree split --prefix=$split_prefix FETCH_HEAD' ($split_head)" >&2
        echo "      The split branch was not honestly produced from upstream master." >&2
        exit 1
    fi
    echo "$rev is contained in 'git subtree split --prefix=$split_prefix FETCH_HEAD' ($split_head)"
fi

echo "GOOD"

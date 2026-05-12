// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

use std::env;
use std::path::PathBuf;
use std::process::Command;

/// A possible error returned by any of the linters.
///
/// The error string should explain the failure type and list all violations.
pub type LintError = String;
pub type LintResult = Result<(), LintError>;
pub type LintFn = fn() -> LintResult;

/// Return the git command
///
/// Lint functions should use this command, so that only files tracked by git are considered and
/// temporary and untracked files are ignored. For example, instead of 'grep', 'git grep' should be
/// used.
pub fn git() -> Command {
    let mut git = Command::new("git");
    git.arg("--no-pager");
    git
}

/// Return stdout on success and a LintError on failure, when invalid UTF8 was detected or the
/// command did not succeed.
pub fn check_output(cmd: &mut Command) -> Result<String, LintError> {
    let out = cmd.output().expect("command error");
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).to_string());
    }
    Ok(String::from_utf8(out.stdout)
        .map_err(|e| {
            format!("All path names, source code, messages, and output must be valid UTF8!\n{e}")
        })?
        .trim()
        .to_string())
}

/// Return the git root as utf8, or panic
pub fn get_git_root() -> PathBuf {
    PathBuf::from(check_output(git().args(["rev-parse", "--show-toplevel"])).unwrap())
}

/// Return the commit range, or panic
pub fn commit_range() -> String {
    // Use the env var, if set. E.g. COMMIT_RANGE='HEAD~n..HEAD' for the last 'n' commits.
    env::var("COMMIT_RANGE").unwrap_or_else(|_| {
        // Otherwise, assume that a merge commit exists. This merge commit is assumed
        // to be the base, after which linting will be done. If the merge commit is
        // HEAD, the range will be empty.
        format!(
            "{}..HEAD",
            check_output(git().args(["rev-list", "--max-count=1", "--merges", "HEAD"]))
                .expect("check_output failed")
        )
    })
}

/// Return all subtree paths
pub fn get_subtrees() -> Vec<&'static str> {
    // Keep in sync with [test/lint/README.md#git-subtree-checksh]
    vec![
        "src/crc32c",
        "src/crypto/ctaes",
        "src/ipc/libmultiprocess",
        "src/leveldb",
        "src/minisketch",
        "src/secp256k1",
    ]
}

/// Description of a subtree imported via 'git subtree split'.
///
/// Such subtrees are not pulled directly from upstream master; instead, upstream
/// publishes a 'split' branch produced by 'git subtree split --prefix=<prefix>'
/// of master, and only that subdirectory is consumed here. To verify that the
/// split branch was honestly produced from master (and not tampered with), the
/// lint runner re-runs the deterministic split locally and confirms the
/// recorded subtree commit is reachable from the result.
pub struct SplitSubtree {
    /// Path of the subtree within this repository.
    pub path: &'static str,
    /// Upstream repository URL to fetch from.
    pub upstream_url: &'static str,
    /// Branch on the upstream repository to fetch and split.
    pub upstream_ref: &'static str,
    /// Branch containing the published split history, if different.
    pub upstream_split_ref: Option<&'static str>,
    /// Prefix passed to 'git subtree split --prefix=' on the upstream side.
    pub split_prefix: &'static str,
}

/// Return all subtrees imported from a 'git subtree split' branch.
pub fn get_split_subtrees() -> Vec<SplitSubtree> {
    vec![SplitSubtree {
        path: "src/ipc/libmultiprocess",
        upstream_url: "https://github.com/bitcoin-core/libmultiprocess.git",
        upstream_ref: "master",
        upstream_split_ref: Some("lib"),
        split_prefix: "lib",
    }]
}

/// Return the pathspecs to exclude by default
pub fn get_pathspecs_default_excludes() -> Vec<String> {
    get_subtrees()
        .iter()
        .chain(&[
            "doc/release-notes/release-notes-*", // archived notes
        ])
        .map(|s| format!(":(exclude){s}"))
        .collect()
}

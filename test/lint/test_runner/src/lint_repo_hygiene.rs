// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

use std::process::Command;

use crate::util::{commit_range, get_split_subtrees, get_subtrees, git, LintResult};

pub fn lint_subtree() -> LintResult {
    // This only checks that the trees are pure subtrees, it is not doing a full
    // check with -r to not have to fetch all the remotes.
    let mut good = true;
    for subtree in get_subtrees() {
        good &= Command::new("test/lint/git-subtree-check.sh")
            .arg(subtree)
            .status()
            .expect("command_error")
            .success();
    }
    // For subtrees imported from a 'git subtree split' branch, additionally
    // verify that the recorded subtree commit could have been produced by
    // splitting upstream master at the documented prefix. This requires a
    // network fetch into FETCH_HEAD, which git-subtree-check.sh -s reads.
    for sub in get_split_subtrees() {
        // Fetch the published split branch first so the recorded subtree
        // commit exists locally for the implicit '-r' check. Then fetch the
        // source branch so FETCH_HEAD points to what should be split.
        for fetch_ref in sub
            .upstream_split_ref
            .into_iter()
            .chain(std::iter::once(sub.upstream_ref))
        {
            good &= git()
                .args(["fetch", "--quiet", sub.upstream_url, fetch_ref])
                .status()
                .expect("command_error")
                .success();
        }
        good &= Command::new("test/lint/git-subtree-check.sh")
            .args(["-s", sub.split_prefix, sub.path])
            .status()
            .expect("command_error")
            .success();
    }
    if good {
        Ok(())
    } else {
        Err("".to_string())
    }
}

pub fn lint_scripted_diff() -> LintResult {
    if Command::new("test/lint/commit-script-check.sh")
        .arg(commit_range())
        .status()
        .expect("command error")
        .success()
    {
        Ok(())
    } else {
        Err("".to_string())
    }
}

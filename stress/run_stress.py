#!/usr/bin/env python3
"""Run functional tests repeatedly and in parallel against one build.

  run_stress.py prepare --srcdir DIR --builddir DIR
      Point BUILDDIR/test/config.ini at downloaded tests and cross-built binaries.

  run_stress.py run --srcdir DIR --builddir DIR --iterations N --parallel P TEST [TEST ...]
      Run each TEST (a file name in SRCDIR/test/functional) N times, P at a time.

This file is not part of the PR.
"""

import argparse
import concurrent.futures
import os
import pathlib
import shutil
import statistics
import subprocess
import sys
import time


def prepare(args):
    srcdir = pathlib.Path(args.srcdir).resolve()
    builddir = pathlib.Path(args.builddir).resolve()
    config = builddir / "test" / "config.ini"
    replacements = {
        "SRCDIR=": f"SRCDIR={srcdir}",
        "BUILDDIR=": f"BUILDDIR={builddir}",
        "RPCAUTH=": f"RPCAUTH={srcdir / 'share' / 'rpcauth' / 'rpcauth.py'}",
    }
    lines = config.read_text(encoding="utf8").splitlines()
    for index, line in enumerate(lines):
        for prefix, new_line in replacements.items():
            if line.startswith(prefix):
                lines[index] = new_line
    config.write_text("\n".join(lines) + "\n", encoding="utf8")
    print(config.read_text(encoding="utf8"))


def create_cache(args, functional_dir, configfile, workdir):
    """Create the cached chain once, as test_runner.py does, so that parallel runs do not race to create it."""
    cachedir = workdir / "cache"
    if not cachedir.exists():
        subprocess.run([sys.executable, str(functional_dir / "create_cache.py"), f"--cachedir={cachedir}",
                        f"--tmpdir={workdir / 'create-cache'}", f"--configfile={configfile}",
                        f"--timeout-factor={args.timeout_factor}"], check=True)
    return cachedir


def run_one(args, functional_dir, configfile, cachedir, workdir, test, index, seed):
    name = f"{pathlib.Path(test).stem}-{index:03d}"
    tmpdir = workdir / name
    log = workdir / f"{name}.log"
    cmd = [sys.executable, str(functional_dir / test), f"--tmpdir={tmpdir}", f"--portseed={seed}",
           f"--cachedir={cachedir}", f"--configfile={configfile}", f"--timeout-factor={args.timeout_factor}"]
    start = time.monotonic()
    with open(log, "wb") as f:
        try:
            code = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, timeout=args.run_timeout).returncode
        except subprocess.TimeoutExpired:
            code = "timeout"
    duration = time.monotonic() - start
    # 77 is the functional test framework's exit code for a skipped test.
    status = {0: "pass", 77: "skip"}.get(code, "FAIL")
    if status != "FAIL":
        log.unlink()
        shutil.rmtree(tmpdir, ignore_errors=True)
    print(f"{status:4} {name} {duration:6.1f}s" + ("" if status != "FAIL" else f"  (exit {code}, see {log})"), flush=True)
    return test, status, duration


def run(args):
    srcdir = pathlib.Path(args.srcdir).resolve()
    functional_dir = pathlib.Path(args.functional_dir).resolve() if args.functional_dir else srcdir / "test" / "functional"
    configfile = pathlib.Path(args.builddir).resolve() / "test" / "config.ini"
    workdir = pathlib.Path(args.workdir).resolve()
    workdir.mkdir(parents=True, exist_ok=True)

    tests = []
    for test in args.tests:
        if (functional_dir / test).exists():
            tests.append(test)
        else:
            print(f"skip {test}: not in {functional_dir}")

    cachedir = create_cache(args, functional_dir, configfile, workdir)
    jobs = [(test, index) for index in range(args.iterations) for test in tests]
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as pool:
        # Consecutive port seeds give each concurrent run its own port range.
        futures = [pool.submit(run_one, args, functional_dir, configfile, cachedir, workdir, test, index, 1 + number % 400)
                   for number, (test, index) in enumerate(jobs)]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    lines = [f"### Stress: {args.label or srcdir.name} ({args.iterations} runs each, {args.parallel} at a time)", "",
             "| Test | Pass | Fail | Skip | Median | Slowest |", "| --- | --- | --- | --- | --- | --- |"]
    failed = 0
    for test in tests:
        mine = [(status, duration) for name, status, duration in results if name == test]
        count = {status: sum(1 for s, _ in mine if s == status) for status in ("pass", "FAIL", "skip")}
        durations = [duration for _, duration in mine]
        failed += count["FAIL"]
        lines.append(f"| {test} | {count['pass']} | {count['FAIL']} | {count['skip']} | "
                     f"{statistics.median(durations):.0f}s | {max(durations):.0f}s |")
    summary = "\n".join(lines) + "\n"
    print(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf8") as f:
            f.write(summary + "\n")
    sys.exit(1 if failed or not tests else 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("--srcdir", required=True, help="directory holding test/functional and share/rpcauth")
    p.add_argument("--builddir", required=True, help="directory holding bin/ and test/config.ini")
    p.set_defaults(func=prepare)
    r = sub.add_parser("run")
    r.add_argument("--srcdir", required=True, help="directory holding test/functional")
    r.add_argument("--builddir", required=True, help="directory holding bin/ and test/config.ini")
    r.add_argument("--functional-dir", help="directory holding the test scripts (default: SRCDIR/test/functional)")
    r.add_argument("--workdir", default="stress-work", help="where test directories and failure logs go")
    r.add_argument("--iterations", type=int, default=10)
    r.add_argument("--parallel", type=int, default=os.cpu_count())
    r.add_argument("--timeout-factor", type=float, default=10)
    r.add_argument("--run-timeout", type=float, default=1800, help="seconds before one run is killed")
    r.add_argument("--label", default="")
    r.add_argument("tests", nargs="+")
    r.set_defaults(func=run)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

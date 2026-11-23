#!/usr/bin/env python3
"""Direct checks of what bitcoin/bitcoin#36716 changes, for a Windows build.

Unlike the functional tests in the PR, these measure the symptom itself:

- CPU use of the node while TCP urgent data is pending on an idle P2P or RPC
  connection. Before the change the socket thread spins on select().
- How long a refused outbound connection takes to be noticed. Windows reports
  a failed non-blocking connect() only in the select() exception set, so this
  shows that connecting still monitors it.

This file is not part of the PR. It uses the functional test framework of the
checkout named by the FUNCTIONAL_DIR environment variable.
"""

import os
import socket
import sys
import time

sys.path.insert(0, os.environ["FUNCTIONAL_DIR"])

from test_framework.messages import MAGIC_BYTES, msg_version  # noqa: E402
from test_framework.p2p import P2PInterface, P2P_VERSION  # noqa: E402
from test_framework.test_framework import BitcoinTestFramework  # noqa: E402
from test_framework.util import p2p_port, rpc_port  # noqa: E402

CONNECT_TIMEOUT_MS = 30000


def process_cpu_seconds(pid):
    """User plus kernel CPU time used by a process so far."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            times = [wintypes.FILETIME() for _ in range(4)]
            if not kernel32.GetProcessTimes(handle, *[ctypes.byref(t) for t in times]):
                raise ctypes.WinError(ctypes.get_last_error())
            return sum(((t.dwHighDateTime << 32) | t.dwLowDateTime) / 1e7 for t in times[2:])
        finally:
            kernel32.CloseHandle(handle)
    with open(f"/proc/{pid}/stat", encoding="utf8") as f:
        fields = f.read().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


class SocketChecks(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_argument("--seconds", type=float, default=10,
                            help="how long to measure each CPU phase")
        parser.add_argument("--max-load", type=float, default=0.25,
                            help="fail if the node uses more CPU seconds per second than this while urgent data is pending")
        parser.add_argument("--max-connect-seconds", type=float, default=15,
                            help="fail if a refused connection takes longer than this to be noticed")
        parser.add_argument("--report-only", action="store_true",
                            help="print the measurements without failing (for a build without the change)")
        parser.add_argument("--label", default="", help="name of this build in the summary")

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[f"-timeout={CONNECT_TIMEOUT_MS}"]]

    def measure(self, name):
        pid = self.nodes[0].process.pid
        cpu, start = process_cpu_seconds(pid), time.monotonic()
        time.sleep(self.options.seconds)
        load = (process_cpu_seconds(pid) - cpu) / (time.monotonic() - start)
        self.log.info(f"{name}: {load:.3f} CPU seconds per second")
        self.results.append((name, f"{load:.3f}"))
        return load

    def p2p_connection(self, *, urgent):
        node = self.nodes[0]
        builder = P2PInterface()
        builder.magic_bytes = MAGIC_BYTES[self.chain]
        version = msg_version()
        version.nVersion = P2P_VERSION
        peer = socket.create_connection(("127.0.0.1", p2p_port(0)), timeout=10)
        self.wait_until(lambda: len(node.getpeerinfo()) == 1)
        peer.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if urgent:
            assert peer.send(b"U", socket.MSG_OOB) == 1
        peer.sendall(builder.build_message(version))
        # The node processed the ordinary data, so it is idle from here on.
        self.wait_until(lambda: node.getpeerinfo()[0]["version"] == P2P_VERSION)
        return peer

    def check_cpu(self):
        node = self.nodes[0]
        failures = []
        time.sleep(2)
        self.measure("idle, no connections")

        with self.p2p_connection(urgent=False):
            self.measure("P2P connection, no urgent data")
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)

        with self.p2p_connection(urgent=True):
            load = self.measure("P2P connection, urgent byte pending")
            still_connected = len(node.getpeerinfo()) == 1
        self.results.append(("P2P peer still connected after urgent byte", str(still_connected)))
        if load > self.options.max_load:
            failures.append(f"node spins on P2P urgent data ({load:.3f})")
        if not still_connected:
            failures.append("P2P peer was disconnected after an urgent byte")
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)

        with socket.create_connection(("127.0.0.1", rpc_port(0)), timeout=10) as rpc:
            rpc.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            assert rpc.send(b"U", socket.MSG_OOB) == 1
            load = self.measure("RPC connection, urgent byte pending")
            # The server must still answer requests.
            node.getblockcount()
        if load > self.options.max_load:
            failures.append(f"node spins on RPC urgent data ({load:.3f})")
        return failures

    def check_refused_connect(self):
        node = self.nodes[0]
        # Find a port nothing listens on.
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            closed_port = probe.getsockname()[1]
        dest = f"127.0.0.1:{closed_port}"
        log_path = node.debug_log_path
        offset = os.path.getsize(log_path)
        start = time.monotonic()
        node.addnode(dest, "onetry")
        outcome = None

        def decided():
            nonlocal outcome
            with open(log_path, encoding="utf8", errors="replace") as f:
                f.seek(offset)
                log = f.read()
            if f"connect() to {dest} failed" in log:
                outcome = "refused"
            elif f"connection attempt to {dest} timed out" in log:
                outcome = "timed out"
            return outcome is not None

        self.wait_until(decided, timeout=CONNECT_TIMEOUT_MS / 1000 + 30)
        elapsed = time.monotonic() - start
        self.log.info(f"refused connect noticed as '{outcome}' after {elapsed:.1f}s")
        self.results.append(("refused connect() noticed as", outcome))
        self.results.append(("refused connect() noticed after", f"{elapsed:.1f}s (connect timeout {CONNECT_TIMEOUT_MS // 1000}s)"))
        if outcome != "refused" or elapsed > self.options.max_connect_seconds:
            return [f"refused connect() was noticed as '{outcome}' after {elapsed:.1f}s"]
        return []

    def run_test(self):
        self.results = []
        failures = self.check_cpu() + self.check_refused_connect()
        verdict = "report only" if self.options.report_only else ("FAIL" if failures else "pass")
        lines = [f"### Socket checks: {self.options.label or 'node'} ({verdict})", "",
                 "| Measurement | Result |", "| --- | --- |"]
        lines += [f"| {name} | {value} |" for name, value in self.results]
        lines += [""] + [f"- {failure}" for failure in failures] + [""]
        summary = "\n".join(lines)
        print(summary)
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf8") as f:
                f.write(summary + "\n")
        if failures and not self.options.report_only:
            raise AssertionError("; ".join(failures))


if __name__ == '__main__':
    SocketChecks(__file__).main()

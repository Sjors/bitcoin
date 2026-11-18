#!/usr/bin/env python3
"""Does this operating system accumulate TCP urgent data that nobody reads?

Most systems keep a single urgent ("out-of-band") byte per socket, so an
application that ignores urgent data loses nothing. RFC 6093 section 3.3
warns that some systems instead queue every urgent byte they receive, and
old Windows versions (XP and earlier) could exhaust kernel memory that way.
This probe answers the question for the machine that runs the receiver, with
a yes or no.

Context: https://github.com/bitcoin/bitcoin/pull/36716 stops monitoring the
select() exception set on established connections, so urgent data is ignored
there. That is only fine if ignored urgent data does not pile up.

Simplest use, on the machine to test (for example Windows):

    python tcp_urgent_queue_probe.py

That starts a receiver ("sink") and a sender in one process and connects them
over loopback. To test the real network path instead, run the sink on the
machine to test and the sender on another machine in the same LAN:

    python tcp_urgent_queue_probe.py --sink --bind 0.0.0.0
    python tcp_urgent_queue_probe.py --connect <address>:28555

How it works. The sink waits for readability only, reads ordinary data with
recv() and never asks for urgent data, like an application that ignores it.
The sender drives it over a separate control connection:

 1. Flood. The sender sends single urgent bytes, and nothing else, on one
    connection. Afterwards the sink counts how many urgent bytes the kernel
    still hands back with recv(MSG_OOB): 0 or 1 means a single byte buffer,
    many means a queue. On Windows it also watches the system-wide nonpaged
    pool, where socket data is buffered, and closes the connection if the
    pool keeps growing.

 2. Limit. Some systems end the connection themselves once too many urgent
    bytes are unread. If the flood connection died, the sender finds out
    where: one urgent byte at a time on a fresh connection, asking the sink
    after each byte whether its side is still open.

 3. Churn. Such a limit bounds what one connection can hold, so what remains
    is whether aborting connections this way leaks memory. The sender opens
    and aborts many connections with urgent data, in rounds that alternate
    with the same number of plain connections. A leak would add up, so the
    verdict rests on the net nonpaged pool change over all rounds. The plain
    rounds tell a leak apart from unrelated activity on the machine.

The last line is one of:

    RESULT: NO            unread urgent data does not accumulate
    RESULT: YES           unread urgent data accumulates in the kernel
    RESULT: INCONCLUSIVE  with the reason

A fast sender can merge several urgent bytes into one TCP segment. Only the
last byte of a segment is then urgent and the rest arrives as ordinary data.
The sink counts those separately; use --delay-us if too many are merged.

Tested on 2026-11-18 with these receivers:

  * Windows 11 Home 26H2, build 26300.9711 (Python 3.12), over loopback and
    from a macOS sender in the same LAN: NO. This Windows queues up to 16
    unread urgent bytes per connection and aborts the connection when the
    17th arrives; aborting 12500 connections that way showed no leak.
    Older Windows versions were not tested.
  * macOS 27.2.1 (Python 3.10), over loopback: NO, a single byte buffer.

Not tested on Linux in this form.

Only loopback and private (RFC 1918, link-local, unique-local) targets are
accepted. Needs only the Python 3 standard library.
"""

import argparse
import errno
import ipaddress
import json
import os
import platform
import select
import socket
import struct
import sys
import threading
import time

MIB = 1024 * 1024
# More unread urgent bytes than this still held by the kernel means a queue.
QUEUE_YES = 1000
# Nonpaged pool growth (Windows) during the flood that counts as accumulation.
GROWTH_YES_MIB = 64
# Net nonpaged pool growth over the churn rounds that counts as a leak.
LEAK_YES_MIB = 32
# Fewer urgent bytes than this actually delivered is too little to conclude "no".
MIN_URGENT = 100_000
# Seconds to let the kernel settle before a memory sample that is compared.
SETTLE = 3


def read_kernel_memory():
    """Return (nonpaged pool bytes, available physical bytes), or None if unavailable."""
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class PerformanceInformation(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("CommitTotal", ctypes.c_size_t),
                ("CommitLimit", ctypes.c_size_t),
                ("CommitPeak", ctypes.c_size_t),
                ("PhysicalTotal", ctypes.c_size_t),
                ("PhysicalAvailable", ctypes.c_size_t),
                ("SystemCache", ctypes.c_size_t),
                ("KernelTotal", ctypes.c_size_t),
                ("KernelPaged", ctypes.c_size_t),
                ("KernelNonpaged", ctypes.c_size_t),
                ("PageSize", ctypes.c_size_t),
                ("HandleCount", wintypes.DWORD),
                ("ProcessCount", wintypes.DWORD),
                ("ThreadCount", wintypes.DWORD),
            ]

        info = PerformanceInformation()
        info.cb = ctypes.sizeof(info)
        if not ctypes.windll.psapi.GetPerformanceInfo(ctypes.byref(info), info.cb):
            return None
        return info.KernelNonpaged * info.PageSize, info.PhysicalAvailable * info.PageSize
    except Exception:
        return None


def describe_os():
    """Name the operating system precisely enough to compare results."""
    if os.name == "nt":
        try:
            import winreg

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
                def value(name):
                    return winreg.QueryValueEx(key, name)[0]

                edition = {"Core": "Home", "Professional": "Pro"}.get(value("EditionID"), value("EditionID"))
                return (f"Windows {platform.release()} {edition} {value('DisplayVersion')}, "
                        f"build {value('CurrentBuild')}.{value('UBR')}")
        except OSError:
            pass
    return platform.platform()


def describe_error(e):
    code = getattr(e, "winerror", None) or e.errno
    return f"{errno.errorcode.get(e.errno, type(e).__name__)} ({code})"


def format_pool(sample, baseline):
    if sample is None or baseline is None:
        return "nonpaged pool n/a"
    return f"nonpaged pool {sample[0] / MIB:8.1f} MiB ({(sample[0] - baseline[0]) / MIB:+8.1f})"


class Lines:
    """Newline-delimited messages over a blocking socket."""

    def __init__(self, sock):
        self.sock = sock
        self.buffer = b""

    def pending(self):
        return b"\n" in self.buffer

    def send(self, text):
        self.sock.sendall(text.encode() + b"\n")

    def receive(self):
        """Return the next line, or None once the other side is gone."""
        while not self.pending():
            try:
                chunk = self.sock.recv(65536)
            except OSError:
                return None
            if not chunk:
                return None
            self.buffer += chunk
        line, _, self.buffer = self.buffer.partition(b"\n")
        return line.decode()


class Connection:
    """The sink's end of a data connection, read like an application that ignores urgent data."""

    def __init__(self, sock):
        sock.setblocking(False)
        self.sock = sock
        self.ordinary = 0
        # Why the connection ended as seen from here, or None while it is open.
        self.dead = None

    def drain(self):
        """Read whatever ordinary data is readable. Never asks for urgent data."""
        while self.dead is None:
            try:
                if not select.select([self.sock], [], [], 0)[0]:
                    return
                chunk = self.sock.recv(65536)
            except (BlockingIOError, InterruptedError):
                return
            except OSError as e:
                self.dead = describe_error(e)
                return
            if not chunk:
                self.dead = "closed by the sender"
                return
            self.ordinary += len(chunk)

    def count_urgent(self):
        """Return how many urgent bytes the kernel hands back with recv(MSG_OOB)."""
        queued = 0
        while self.dead is None and queued < 100 * MIB:
            try:
                chunk = self.sock.recv(65536, socket.MSG_OOB)
            except OSError:
                break
            if not chunk:
                break
            queued += len(chunk)
        return queued

    def close(self, reason=None):
        if reason and self.dead is None:
            self.dead = reason
        try:
            self.sock.close()
        except OSError:
            pass


class Sink:
    """Accept a sender and do what it asks over the control connection."""

    def __init__(self, bind, port, *, interval, max_growth_mib, print_report=True):
        self.listener = socket.create_server((bind, port), backlog=64)
        self.address = self.listener.getsockname()
        self.interval = interval
        self.max_growth_mib = max_growth_mib
        self.print_report = print_report
        self.current = None
        self.guard = None

    def check_guard(self):
        """While flooding, report the nonpaged pool and stop if it keeps growing."""
        guard = self.guard
        now = time.monotonic()
        if guard is None or now - guard["last"] < self.interval:
            return
        guard["last"] = now
        sample = read_kernel_memory()
        ordinary = self.current.ordinary if self.current else 0
        print(f"sink: {now - guard['start']:7.1f}s  {ordinary:>9} ordinary bytes read  "
              f"{format_pool(sample, guard['baseline'])}", flush=True)
        if sample is None or guard["baseline"] is None:
            return
        growth = (sample[0] - guard["baseline"][0]) / MIB
        guard["peak"] = max(guard["peak"], growth)
        if growth > self.max_growth_mib and self.current and self.current.dead is None:
            guard["tripped"] = True
            self.current.close("closed by the sink because the nonpaged pool kept growing")

    def handle(self, command, argument):
        """Carry out one request from the sender and return the reply."""
        current = self.current
        if command == "HELLO":
            return {"os": describe_os(), "memory": read_kernel_memory() is not None}
        if command == "NEW":
            if current:
                current.close()
            self.listener.settimeout(15)
            try:
                sock, _ = self.listener.accept()
            except OSError as e:
                self.current = None
                return {"error": f"no data connection arrived: {describe_error(e)}"}
            self.current = Connection(sock)
            return {}
        if command == "GUARD":
            if argument == "1":
                now = time.monotonic()
                baseline = read_kernel_memory()
                self.guard = {"baseline": baseline, "peak": 0.0, "tripped": False, "start": now, "last": now}
                print(f"sink: flood     {format_pool(baseline, baseline)}", flush=True)
                return {}
            guard, self.guard = self.guard, None
            return {"tripped": guard["tripped"], "peak_mib": guard["peak"]}
        if command == "STATE":
            time.sleep(float(argument or 0) / 1000)
            current.drain()
            return {"dead": current.dead, "ordinary": current.ordinary,
                    "tripped": bool(self.guard and self.guard["tripped"])}
        if command == "COUNT":
            current.drain()
            return {"queued": current.count_urgent(), "dead": current.dead, "ordinary": current.ordinary}
        if command == "MEM":
            time.sleep(float(argument or 0))
            sample = read_kernel_memory()
            return {"nonpaged": sample[0] if sample else None}
        if command == "CLOSE":
            if current:
                current.close()
            self.current = None
            return {}
        if command == "REPORT":
            if self.print_report:
                print("\n" + json.loads(argument), flush=True)
            return {}
        return {"error": f"unknown command {command}"}

    def run(self):
        control, peer = self.listener.accept()
        control.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        lines = Lines(control)
        print(f"sink: sender connected from {peer[0]}", flush=True)
        try:
            while True:
                watched = [control]
                if self.current and self.current.dead is None:
                    watched.append(self.current.sock)
                readable = [] if lines.pending() else select.select(watched, [], [], 0.2)[0]
                if self.current and self.current.sock in readable:
                    self.current.drain()
                self.check_guard()
                if control not in readable and not lines.pending():
                    continue
                line = lines.receive()
                if line is None:
                    print("sink: the sender went away", flush=True)
                    break
                command, _, argument = line.partition(" ")
                if command == "BYE":
                    lines.send("{}")
                    break
                lines.send(json.dumps(self.handle(command, argument)))
        finally:
            if self.current:
                self.current.close()
            control.close()
            self.listener.close()


def resolve_private_target(host, port):
    family, _, _, _, sockaddr = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0]
    address = ipaddress.ip_address(sockaddr[0].split("%")[0])
    if not (address.is_loopback or address.is_private or address.is_link_local):
        sys.exit(f"Refusing {address}: only loopback and private addresses are accepted. "
                 "Run this against a machine you own, locally or in the same LAN.")
    return family, sockaddr


class Sender:
    """Drive a sink through the flood, limit and churn steps and build the report."""

    def __init__(self, host, port, args):
        self.args = args
        self.family, self.sockaddr = resolve_private_target(host, port)
        self.control = Lines(self.connect())
        self.control.sock.settimeout(120)

    def connect(self, *, reset_on_close=False):
        sock = socket.socket(self.family, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect(self.sockaddr)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if reset_on_close:
            # Close with a reset, so thousands of short connections do not pile up in TIME_WAIT.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("HH" if os.name == "nt" else "ii", 1, 0))
        return sock

    def ask(self, command):
        self.control.send(command)
        reply = self.control.receive()
        if reply is None:
            raise ConnectionError("the sink went away")
        reply = json.loads(reply)
        if "error" in reply:
            raise ConnectionError(reply["error"])
        return reply

    def open_data(self, **kwargs):
        """Open a data connection and have the sink accept it as its current one."""
        sock = self.connect(**kwargs)
        self.ask("NEW")
        sock.settimeout(self.args.block_timeout)
        return sock

    def memory(self, settle=0):
        return self.ask(f"MEM {settle}")["nonpaged"]

    def flood(self):
        """Send urgent bytes on one connection for as long as it lasts."""
        args = self.args
        before = self.memory()
        data = self.open_data()
        self.ask("GUARD 1")
        delay = args.delay_us / 1e6
        sent = 0
        blocked = False
        send_error = None
        reason = "sent the requested number of urgent bytes"
        start = last_report = time.monotonic()
        try:
            while sent < args.count:
                try:
                    data.send(b"U", socket.MSG_OOB)
                except socket.timeout:
                    blocked = True
                    reason = f"a send blocked for {args.block_timeout:g} s (flow control)"
                    break
                except OSError as e:
                    send_error = describe_error(e)
                    reason = f"the next send failed with {send_error}"
                    break
                sent += 1
                if delay:
                    time.sleep(delay)
                if sent % 500:
                    continue
                now = time.monotonic()
                if now - last_report >= args.interval:
                    last_report = now
                    print(f"sender: {now - start:7.1f}s  {sent:>10} urgent bytes sent", flush=True)
                    if now - start > args.duration:
                        reason = f"reached the {args.duration:g} s time limit"
                        break
        except KeyboardInterrupt:
            reason = "interrupted"
        elapsed = time.monotonic() - start
        print(f"sender: flood stopped, {reason}: {sent} urgent bytes in {elapsed:.1f} s", flush=True)

        # Leave the connection open while the sink takes its measurements.
        time.sleep(args.hold)
        count = self.ask("COUNT")
        still_open = self.memory()
        guard = self.ask("GUARD 0")
        data.close()
        self.ask("CLOSE")
        closed = self.memory(SETTLE)
        return {
            "sent": sent, "elapsed": elapsed, "reason": reason, "blocked": blocked,
            # How the connection ended, as seen by the receiver or else by the sender. None if it did not.
            "died": count["dead"] or send_error, "receiver_saw": count["dead"],
            "tripped": guard["tripped"], "queued": count["queued"],
            "ordinary": count["ordinary"], "peak_mib": guard["peak_mib"],
            "before": before, "open": still_open, "closed": closed,
        }

    def find_limit(self):
        """Return how many unread urgent bytes a connection survives, or None if all of --max-steps."""
        data = self.open_data()
        limit = None
        why = None
        try:
            for step in range(1, self.args.max_steps + 1):
                try:
                    data.send(b"U", socket.MSG_OOB)
                except OSError as e:
                    limit, why = step - 1, describe_error(e)
                    break
                state = self.ask("STATE 100")
                if state["dead"]:
                    limit, why = step - 1, state["dead"]
                    break
        finally:
            data.close()
            self.ask("CLOSE")
        return limit, why

    def confirm_limit(self, limit):
        """Leave exactly `limit` urgent bytes unread and report what the sink then sees."""
        data = self.open_data()
        try:
            for _ in range(limit):
                data.send(b"U", socket.MSG_OOB)
                time.sleep(0.005)
            self.ask("STATE 200")
            return self.ask("COUNT")
        finally:
            data.close()
            self.ask("CLOSE")

    def churn(self, cycles, urgent):
        """Open and close `cycles` connections; with `urgent` > 0, have the kernel abort each first."""
        done = aborted = 0
        for _ in range(cycles):
            try:
                data = self.open_data(reset_on_close=True)
            except OSError as e:
                print(f"sender: stopped after {done} connections: {describe_error(e)}", flush=True)
                break
            if urgent:
                # Twice, in case the first urgent bytes were merged into one segment.
                for wait in (0.2, 1):
                    try:
                        for _ in range(urgent):
                            data.send(b"U", socket.MSG_OOB)
                        data.settimeout(wait)
                        data.recv(1)
                    except socket.timeout:
                        continue
                    except OSError:
                        pass
                    aborted += 1
                    break
            data.close()
            done += 1
        self.ask("CLOSE")
        return done, aborted

    def leak_check(self, limit):
        """Compare nonpaged pool growth of aborted connections with plain ones."""
        args = self.args
        rounds = []
        sample = self.memory(SETTLE)
        for number in range(1, args.rounds + 1):
            row = {}
            for kind, urgent in (("plain", 0), ("aborted", limit + 1)):
                start = time.monotonic()
                done, aborted = self.churn(args.cycles, urgent)
                elapsed = time.monotonic() - start
                previous, sample = sample, self.memory(SETTLE)
                row[kind] = {"done": done, "aborted": aborted,
                             "growth": None if sample is None else (sample - previous) / MIB}
                growth = "" if sample is None else f", nonpaged pool {row[kind]['growth']:+.1f} MiB"
                detail = f" ({aborted} aborted by the receiver)" if urgent else ""
                print(f"sender: round {number}: {done} {kind} connections{detail} in {elapsed:.1f} s{growth}", flush=True)
            rounds.append(row)
        return rounds

    def run(self):
        hello = self.ask("HELLO")
        print(f"sender: connected to the sink at {self.sockaddr[0]}:{self.sockaddr[1]} ({hello['os']})", flush=True)
        lines = [f"Receiver: {hello['os']}", f"Sender:   {describe_os()}"]

        flood = self.flood()
        lines.append(f"Flood: {flood['sent']} urgent bytes on one connection in {flood['elapsed']:.1f} s; "
                     f"stopped because {flood['reason']}")
        if flood["died"]:
            lines.append(f"  The receiver's side of the connection: {flood['receiver_saw'] or 'still open'}")
        else:
            lines.append(f"  Arrived as urgent data: about {flood['sent'] - flood['ordinary']}; "
                         f"merged into ordinary data: {flood['ordinary']}")
            lines.append(f"  Unread urgent bytes the kernel still held at the end: {flood['queued']}")
        if flood["before"] is not None:
            lines.append(f"  Nonpaged pool: {flood['before'] / MIB:.1f} MiB before, {flood['open'] / MIB:.1f} MiB with the "
                         f"connection open, {flood['closed'] / MIB:.1f} MiB after closing; peak growth {flood['peak_mib']:+.1f} MiB")
        else:
            lines.append("  Kernel memory is only measured on a Windows receiver; the result rests on the urgent byte counts.")

        limit = held = rounds = None
        if flood["died"] and not flood["tripped"] and not flood["blocked"]:
            limit, why = self.find_limit()
            if limit is not None:
                confirmed = self.confirm_limit(limit)
                held = confirmed["queued"]
                lines.append(f"Limit: one urgent byte at a time, the receiver's side ended when unread urgent byte "
                             f"{limit + 1} arrived: {why}")
                lines.append(f"  With {limit} unread urgent bytes the connection "
                             f"{'had also ended' if confirmed['dead'] else 'stayed open'} and recv(MSG_OOB) returned {held}")
                rounds = self.leak_check(limit)
                for number, row in enumerate(rounds, 1):
                    def growth(kind):
                        value = row[kind]["growth"]
                        return "n/a" if value is None else f"{value:+.1f} MiB"

                    lines.append(f"Churn round {number}: {row['plain']['done']} plain connections: nonpaged pool {growth('plain')}; "
                                 f"{row['aborted']['done']} connections with {limit + 1} urgent bytes "
                                 f"({row['aborted']['aborted']} aborted by the receiver): {growth('aborted')}")
            else:
                lines.append(f"Limit: one urgent byte at a time, the connection survived {self.args.max_steps} unread urgent bytes")

        lines.append(decide(flood, limit, held, rounds, self.args.max_steps))
        report = "\n".join(lines)
        self.ask("REPORT " + json.dumps(report))
        self.ask("BYE")
        return report


def decide(flood, limit, held, rounds, max_steps):
    """Return the RESULT line."""
    if flood["tripped"]:
        return (f"RESULT: YES - the nonpaged pool kept growing while urgent data went unread "
                f"(stopped at {flood['peak_mib']:+.0f} MiB).")
    if flood["blocked"]:
        return (f"RESULT: NO - the sender was stopped by flow control after {flood['sent']} urgent bytes, "
                "so what the receiver holds is bounded.")
    if flood["died"]:
        if limit is None:
            return (f"RESULT: INCONCLUSIVE - the flood connection ended after {flood['sent']} urgent bytes, but one byte "
                    f"at a time a connection survived {max_steps}. Rerun, or raise --max-steps.")
        aborted = sum(row["aborted"]["aborted"] for row in rounds)
        attempted = sum(row["aborted"]["done"] for row in rounds)
        bound = (f"the receiver holds at most {held} unread urgent bytes per connection and ends the connection "
                 f"when urgent byte {limit + 1} arrives")
        if attempted == 0 or aborted < 0.9 * attempted:
            return (f"RESULT: INCONCLUSIVE - {bound}, but only {aborted} of {attempted} connections "
                    "were aborted in the leak check.")
        if rounds[0]["plain"]["growth"] is None:
            return f"RESULT: NO - {bound}. Kernel memory was not measured."
        # A leak adds up, so judge by the net change over all rounds. Single rounds go up and
        # down by several MiB even on an idle machine.
        during_aborted = sum(row["aborted"]["growth"] for row in rounds)
        during_plain = sum(row["plain"]["growth"] for row in rounds)
        net = during_aborted + during_plain
        split = f"{during_aborted:+.1f} MiB during aborted and {during_plain:+.1f} MiB during plain connections"
        if net < LEAK_YES_MIB:
            return (f"RESULT: NO - {bound}. Aborting {aborted} connections that way showed no leak: the nonpaged pool "
                    f"changed by {net:+.1f} MiB over the whole check ({split}). A leak of "
                    f"{LEAK_YES_MIB * MIB / aborted:.0f} bytes per connection would have added {LEAK_YES_MIB} MiB.")
        if during_aborted - during_plain >= LEAK_YES_MIB / 2:
            return (f"RESULT: YES - {bound}, but aborting {aborted} connections that way grew the nonpaged pool by "
                    f"{net:.0f} MiB ({split}), about {net * MIB / aborted:.0f} bytes per connection.")
        return (f"RESULT: INCONCLUSIVE - {bound}, but the nonpaged pool grew by {net:.0f} MiB during the leak check "
                f"and not specifically for aborted connections ({split}). Something else is using kernel memory; "
                "rerun on a quiet machine.")
    if flood["queued"] > QUEUE_YES:
        return f"RESULT: YES - the kernel was still holding {flood['queued']} unread urgent bytes."
    growth = None if flood["before"] is None else flood["peak_mib"]
    if growth is not None and growth >= GROWTH_YES_MIB:
        return f"RESULT: YES - the nonpaged pool grew by {growth:.0f} MiB while urgent data went unread."
    urgent = flood["sent"] - flood["ordinary"]
    if urgent < MIN_URGENT:
        return (f"RESULT: INCONCLUSIVE - only {urgent} bytes arrived as urgent data. "
                "Rerun with a higher --count, or with --delay-us 100 if most bytes were merged.")
    memory = "" if growth is None else f" and the nonpaged pool grew by at most {growth:.1f} MiB"
    return f"RESULT: NO - after {urgent} unread urgent bytes the kernel held {flood['queued']}{memory}."


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--sink", action="store_true", help="receiver only; also prints the result")
    mode.add_argument("--connect", metavar="HOST:PORT", help="sender only, to a --sink on another machine")
    parser.add_argument("--bind", default="127.0.0.1", help="--sink: address to listen on (default: %(default)s)")
    parser.add_argument("--listen-port", type=int, default=28555, help="--sink: port to listen on (default: %(default)s)")
    parser.add_argument("--count", type=int, default=5_000_000, help="flood: urgent bytes to send (default: %(default)s)")
    parser.add_argument("--duration", type=float, default=600, help="flood: stop after this many seconds (default: %(default)s)")
    parser.add_argument("--delay-us", type=float, default=0, help="flood: pause between urgent bytes, in microseconds (default: %(default)s)")
    parser.add_argument("--max-growth-mib", type=float, default=512,
                        help="sink: end the flood once the nonpaged pool grew by this much (default: %(default)s)")
    parser.add_argument("--block-timeout", type=float, default=15,
                        help="treat a send that blocks this long as flow control (default: %(default)s s)")
    parser.add_argument("--hold", type=float, default=5, help="flood: seconds to keep the connection open after sending (default: %(default)s)")
    parser.add_argument("--max-steps", type=int, default=256,
                        help="limit: give up looking for a per-connection limit after this many urgent bytes (default: %(default)s)")
    parser.add_argument("--cycles", type=int, default=2500, help="churn: connections per round and kind (default: %(default)s)")
    parser.add_argument("--rounds", type=int, default=5, help="churn: rounds of plain, then aborted connections (default: %(default)s)")
    parser.add_argument("--interval", type=float, default=2, help="seconds between progress lines (default: %(default)s)")
    args = parser.parse_args()

    if args.sink:
        sink = Sink(args.bind, args.listen_port, interval=args.interval, max_growth_mib=args.max_growth_mib)
        print(f"sink: {describe_os()}, listening on {sink.address[0]}:{sink.address[1]}. Start the sender with "
              f"--connect <this machine's address>:{sink.address[1]}", flush=True)
        sink.run()
        return

    if args.connect:
        host, _, port = args.connect.rpartition(":")
        host, port = host.strip("[]"), int(port)
    else:
        sink = Sink("127.0.0.1", 0, interval=args.interval, max_growth_mib=args.max_growth_mib, print_report=False)
        threading.Thread(target=sink.run, daemon=True).start()
        host, port = sink.address
    try:
        report = Sender(host, port, args).run()
    except (ConnectionError, OSError) as e:
        report = f"RESULT: INCONCLUSIVE - {e}."
    print("\n" + report)


if __name__ == "__main__":
    main()

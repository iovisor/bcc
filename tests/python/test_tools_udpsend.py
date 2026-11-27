#!/usr/bin/env python3
# Licensed under the Apache License, Version 2.0 (the "License")

import contextlib
import os
import select
import signal
import socket
import subprocess
import time
from unittest import main, skipUnless, TestCase
from utils import kernel_version_ge

TOOLS_DIR = "/bcc/tools/"

if not os.path.exists("/bcc/tools/"):
    TOOLS_DIR = "../../tools/"


def has_ipv6_loopback():
    if not socket.has_ipv6:
        return False
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.bind(("::1", 0))
            return True
    except OSError:
        return False


def parse_event_line(line):
    parts = line.split()
    if len(parts) != 9:
        return None
    try:
        return {
            "ts": float(parts[0]),
            "pid": int(parts[1]),
            "uid": int(parts[2]),
            "comm": parts[3],
            "ip": int(parts[4]),
            "saddr": parts[5],
            "sport": int(parts[6]),
            "daddr": parts[7],
            "dport": int(parts[8]),
        }
    except ValueError:
        return None


@skipUnless(kernel_version_ge(4, 10), "requires kernel >= 4.10")
class UdpsendToolTests(TestCase):
    def _run_udpsend_and_capture(self, send_fn, done_fn):
        proc = subprocess.Popen(
            [TOOLS_DIR + "udpsend.py", "-t"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        stdout_fd = proc.stdout.fileno()
        stderr_fd = proc.stderr.fileno()
        open_fds = [stdout_fd, stderr_fd]
        out_buf = bytearray()
        err_buf = bytearray()
        events = []

        def drain_fds(timeout_s):
            if not open_fds:
                return True
            rlist, _, _ = select.select(open_fds, [], [], timeout_s)
            for fd in rlist:
                chunk = os.read(fd, 65536)
                if not chunk:
                    open_fds.remove(fd)
                elif fd == stdout_fd:
                    out_buf.extend(chunk)
                else:
                    err_buf.extend(chunk)
            return stdout_fd not in open_fds

        def consume_event_lines():
            while b"\n" in out_buf:
                nl = out_buf.index(b"\n")
                line = bytes(out_buf[:nl]).decode("utf-8", "replace")
                del out_buf[:nl + 1]
                ev = parse_event_line(line)
                if ev is not None:
                    self.assertGreaterEqual(
                        ev["ts"], 0.0,
                        "negative -t timestamp in output line: %r" % line,
                    )
                    events.append(ev)

        try:
            # Wait for the table header using raw os.read() + select() so
            # Python's TextIOWrapper buffering cannot hide an already-read line.
            deadline = time.monotonic() + 15.0
            header_seen = False
            while time.monotonic() < deadline and not header_seen:
                remaining = max(0.0, deadline - time.monotonic())
                eof = drain_fds(min(0.2, remaining))
                while b"\n" in out_buf:
                    nl = out_buf.index(b"\n")
                    line = bytes(out_buf[:nl])
                    del out_buf[:nl + 1]
                    if b"PID" in line and b"DPORT" in line:
                        header_seen = True
                        break
                if eof or (not header_seen and proc.poll() is not None):
                    break

            if not header_seen:
                proc.kill()
                rest_out, rest_err = proc.communicate(timeout=5)
                self.fail(
                    "udpsend.py failed to start (rc=%s)\nstdout:\n%s\nstderr:\n%s"
                    % (
                        proc.returncode,
                        (bytes(out_buf) + rest_out).decode("utf-8", "replace"),
                        (bytes(err_buf) + rest_err).decode("utf-8", "replace"),
                    )
                )

            expected = send_fn()

            # Continuously drain stdout/stderr while waiting for all expected
            # events so background UDP output cannot fill the pipe and block
            # udpsend.py. Once all expected events arrive, keep draining for a
            # short grace window to surface any accidental duplicate events.
            capture_deadline = time.monotonic() + 5.0
            grace_deadline = None
            while time.monotonic() < capture_deadline:
                consume_event_lines()
                if grace_deadline is None and done_fn(events, expected):
                    grace_deadline = min(capture_deadline, time.monotonic() + 0.25)
                if grace_deadline is not None and time.monotonic() >= grace_deadline:
                    break
                target = grace_deadline if grace_deadline is not None else capture_deadline
                remaining = max(0.0, target - time.monotonic())
                eof = drain_fds(min(0.05, remaining))
                if eof or proc.poll() is not None:
                    break

            proc.send_signal(signal.SIGINT)
            rest_out, rest_err = proc.communicate(timeout=5)
            out_buf.extend(rest_out)
            err_buf.extend(rest_err)
            consume_event_lines()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=5)

        err = bytes(err_buf).decode("utf-8", "replace")
        self.assertEqual(
            proc.returncode, 0,
            "udpsend.py exited with %s\nstderr:\n%s" % (proc.returncode, err),
        )
        return events, err, expected

    def test_loopback_udp_paths(self):
        ipv6_ok = has_ipv6_loopback()
        my_pid = os.getpid()
        v4_addrs = ("127.0.0.1", "::ffff:127.0.0.1")

        def match(events, sport, dport, daddrs):
            return [
                e for e in events
                if e["pid"] == my_pid
                and e["sport"] == sport
                and e["dport"] == dport
                and e["daddr"] in daddrs
            ]

        def all_expected_seen(events, info):
            v4_s, v4_d = info["v4"]
            if len(match(events, v4_s, v4_d, ("127.0.0.1",))) < 1:
                return False
            if ipv6_ok:
                if len(match(events, *info["v6"], ("::1",))) < 1:
                    return False
                if len(match(events, *info["v4mapped"], v4_addrs)) < 1:
                    return False
                if len(match(events, *info["v6only_mapped"], v4_addrs)) < 1:
                    return False
                if len(match(events, *info["v4mapped_cork"], v4_addrs)) < 2:
                    return False
                mix_s, mix_v6_d, mix_v4_d = info["v6_cork_then_v4mapped"]
                if len(match(events, mix_s, mix_v6_d, ("::1",))) < 1:
                    return False
                if len(match(events, mix_s, mix_v4_d, v4_addrs)) < 1:
                    return False
                if len(match(events, *info["v4mapped_saddr_to_any"][:2], v4_addrs + ("::",))) < 1:
                    return False
                c6_s, c6_a, _ = info["v6_cork_explicit_dest"]
                if len(match(events, c6_s, c6_a, ("::1",))) < 2:
                    return False
            return True

        def send_probes():
            info = {}
            with contextlib.ExitStack() as stack:
                # 1. IPv4 unconnected sendto()
                rx4 = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                tx4 = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                rx4.bind(("127.0.0.1", 0))
                v4_dport = rx4.getsockname()[1]
                tx4.sendto(b"v4", ("127.0.0.1", v4_dport))
                info["v4"] = (tx4.getsockname()[1], v4_dport)

                if ipv6_ok:
                    # 2. Native IPv6 unconnected sendto()
                    rx6 = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
                    tx6 = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
                    rx6.bind(("::1", 0))
                    v6_dport = rx6.getsockname()[1]
                    tx6.sendto(b"v6", ("::1", v6_dport))
                    info["v6"] = (tx6.getsockname()[1], v6_dport)

                    # 3. Dual-stack IPv4-mapped sendto() (IPV6_V6ONLY=0)
                    rx4m = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                    tx4m = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
                    rx4m.bind(("127.0.0.1", 0))
                    mapped_dport = rx4m.getsockname()[1]
                    tx4m.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                    tx4m.sendto(b"v4m", ("::ffff:127.0.0.1", mapped_dport))
                    info["v4mapped"] = (tx4m.getsockname()[1], mapped_dport)

                    # 4. IPV6_V6ONLY=1 failed sendto() to IPv4-mapped destination
                    rx6o = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                    tx6o = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
                    rx6o.bind(("127.0.0.1", 0))
                    v6only_dport = rx6o.getsockname()[1]
                    tx6o.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    try:
                        tx6o.sendto(b"v6o", ("::ffff:127.0.0.1", v6only_dport))
                    except OSError:
                        pass
                    info["v6only_mapped"] = (tx6o.getsockname()[1], v6only_dport)

                    # 5. Dual-stack MSG_MORE corked send to IPv4-mapped followed
                    #    by an addressless sendmsg() to flush the corked frame.
                    rx_cork = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                    tx_cork = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
                    rx_cork.bind(("127.0.0.1", 0))
                    cork_dport = rx_cork.getsockname()[1]
                    tx_cork.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                    tx_cork.sendto(b"c1", socket.MSG_MORE, ("::ffff:127.0.0.1", cork_dport))
                    tx_cork.sendmsg([b"c2"])
                    info["v4mapped_cork"] = (tx_cork.getsockname()[1], cork_dport)

                    # 6. Dual-stack MSG_MORE corked to native IPv6, then an
                    #    explicit sendto() to an IPv4-mapped destination (kernel
                    #    forwards to udp_sendmsg() before checking up->pending).
                    rx_mix6 = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
                    rx_mix4 = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                    tx_mix = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
                    rx_mix6.bind(("::1", 0))
                    rx_mix4.bind(("127.0.0.1", 0))
                    mix_v6_dport = rx_mix6.getsockname()[1]
                    mix_v4_dport = rx_mix4.getsockname()[1]
                    tx_mix.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                    tx_mix.sendto(b"m1", socket.MSG_MORE, ("::1", mix_v6_dport))
                    try:
                        tx_mix.sendto(b"m2", ("::ffff:127.0.0.1", mix_v4_dport))
                    except OSError:
                        pass
                    info["v6_cork_then_v4mapped"] = (
                        tx_mix.getsockname()[1], mix_v6_dport, mix_v4_dport
                    )

                    # 7. Dual-stack socket bound to ::ffff:127.0.0.1 sending
                    #    explicitly to ::. Kernels with the :: -> ::ffff:127.0.0.1
                    #    rewrite forward to udp_sendmsg() and deliver to rx_any;
                    #    older kernels stay on the IPv6 path. Either way, exactly
                    #    1 event must be reported.
                    rx_any = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                    tx_any = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
                    rx_any.bind(("127.0.0.1", 0))
                    rx_any.settimeout(0.2)
                    any_dport = rx_any.getsockname()[1]
                    tx_any.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                    tx_any.bind(("::ffff:127.0.0.1", 0))
                    try:
                        tx_any.sendto(b"any", ("::", any_dport))
                    except OSError:
                        pass
                    rewrote_to_v4 = False
                    try:
                        rewrote_to_v4 = (rx_any.recv(16) == b"any")
                    except OSError:
                        pass
                    info["v4mapped_saddr_to_any"] = (
                        tx_any.getsockname()[1], any_dport, rewrote_to_v4
                    )

                    # 8. Native IPv6 MSG_MORE to port A, then explicit sendto()
                    #    to port B on the same socket: kernel appends to the
                    #    corked flow targeting port A.
                    rx_c6a = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
                    rx_c6b = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
                    tx_c6 = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
                    rx_c6a.bind(("::1", 0))
                    rx_c6b.bind(("::1", 0))
                    c6a_dport = rx_c6a.getsockname()[1]
                    c6b_dport = rx_c6b.getsockname()[1]
                    tx_c6.sendto(b"a1", socket.MSG_MORE, ("::1", c6a_dport))
                    tx_c6.sendto(b"a2", ("::1", c6b_dport))
                    info["v6_cork_explicit_dest"] = (
                        tx_c6.getsockname()[1], c6a_dport, c6b_dport
                    )

            return info

        events, err, info = self._run_udpsend_and_capture(
            send_probes, all_expected_seen
        )

        # Verify IPv4 path
        v4_sport, v4_dport = info["v4"]
        v4_hits = match(events, v4_sport, v4_dport, ("127.0.0.1",))
        self.assertEqual(len(v4_hits), 1, "expected 1 IPv4 event, got %r" % v4_hits)
        self.assertEqual(v4_hits[0]["ip"], 4)
        self.assertGreater(v4_hits[0]["sport"], 0)

        if ipv6_ok:
            self.assertNotIn(
                "tracing IPv4 only", err,
                "IPv6 loopback is available but udpsend degraded to IPv4 only:\n%s" % err,
            )

            # Verify native IPv6 path
            v6_sport, v6_dport = info["v6"]
            v6_hits = match(events, v6_sport, v6_dport, ("::1",))
            self.assertEqual(len(v6_hits), 1, "expected 1 IPv6 event, got %r" % v6_hits)
            self.assertEqual(v6_hits[0]["ip"], 6)
            self.assertGreater(v6_hits[0]["sport"], 0)

            # Verify dual-stack IPv4-mapped path emits exactly 1 IPv4 event
            # (counting both IPv4 and IPv4-mapped IPv6 addresses to catch dups).
            mapped_sport, mapped_dport = info["v4mapped"]
            mapped_hits = match(events, mapped_sport, mapped_dport, v4_addrs)
            self.assertEqual(
                len(mapped_hits), 1,
                "expected 1 deduplicated event for IPv4-mapped send, got %r" % mapped_hits,
            )
            self.assertEqual(mapped_hits[0]["ip"], 4)
            self.assertEqual(mapped_hits[0]["daddr"], "127.0.0.1")

            # Verify IPV6_V6ONLY failed send to IPv4-mapped destination is traced once
            v6only_sport, v6only_dport = info["v6only_mapped"]
            v6only_hits = match(events, v6only_sport, v6only_dport, v4_addrs)
            self.assertEqual(
                len(v6only_hits), 1,
                "expected 1 event for IPV6_V6ONLY v4-mapped attempt, got %r" % v6only_hits,
            )
            self.assertEqual(v6only_hits[0]["ip"], 6)
            self.assertEqual(v6only_hits[0]["daddr"], "::ffff:127.0.0.1")

            # Verify dual-stack MSG_MORE corked IPv4-mapped send + addressless
            # flush emits 2 IPv4 events with the corked destination and no IPv6 dup.
            cork_sport, cork_dport = info["v4mapped_cork"]
            cork_hits = match(events, cork_sport, cork_dport, v4_addrs)
            self.assertEqual(
                len(cork_hits), 2,
                "expected 2 IPv4 events for corked IPv4-mapped sends, got %r" % cork_hits,
            )
            for hit in cork_hits:
                self.assertEqual(hit["ip"], 4)
                self.assertEqual(hit["daddr"], "127.0.0.1")
            cork_v6_dups = [
                e for e in events
                if e["pid"] == my_pid and e["ip"] == 6 and e["sport"] == cork_sport
            ]
            self.assertEqual(
                len(cork_v6_dups), 0,
                "unexpected IPv6 events for corked IPv4-mapped socket: %r" % cork_v6_dups,
            )

            # Verify IPv6-corked socket sending explicitly to IPv4-mapped emits
            # 1 native IPv6 event (for the corked send) and 1 IPv4 event (for
            # the forwarded v4-mapped send), with no duplicate on the v6 path.
            mix_sport, mix_v6_dport, mix_v4_dport = info["v6_cork_then_v4mapped"]
            mix_v6_hits = match(events, mix_sport, mix_v6_dport, ("::1",))
            mix_v4_hits = match(events, mix_sport, mix_v4_dport, v4_addrs)
            self.assertEqual(
                len(mix_v6_hits), 1,
                "expected 1 IPv6 event for corked IPv6 send (no dup on v4-mapped), got %r"
                % mix_v6_hits,
            )
            self.assertEqual(mix_v6_hits[0]["ip"], 6)
            self.assertEqual(
                len(mix_v4_hits), 1,
                "expected 1 IPv4 event for forwarded v4-mapped send, got %r" % mix_v4_hits,
            )
            self.assertEqual(mix_v4_hits[0]["ip"], 4)
            self.assertEqual(mix_v4_hits[0]["daddr"], "127.0.0.1")

            # Verify dual-stack socket bound to ::ffff:127.0.0.1 sending to ::
            # emits exactly 1 event matching the kernel's actual path (IPv4 on
            # kernels with the :: -> ::ffff:127.0.0.1 rewrite, IPv6 on older ones).
            any_sport, any_dport, rewrote_to_v4 = info["v4mapped_saddr_to_any"]
            any_hits = match(events, any_sport, any_dport, v4_addrs + ("::",))
            self.assertEqual(
                len(any_hits), 1,
                "expected 1 event for :: from v4-mapped saddr, got %r" % any_hits,
            )
            if rewrote_to_v4:
                self.assertEqual(any_hits[0]["ip"], 4)
                self.assertEqual(any_hits[0]["daddr"], "127.0.0.1")
            else:
                self.assertEqual(any_hits[0]["ip"], 6)
                self.assertEqual(any_hits[0]["daddr"], "::")

            # Verify native IPv6 MSG_MORE to port A followed by explicit
            # sendto() to port B reports both sends against corked port A.
            c6_sport, c6a_dport, c6b_dport = info["v6_cork_explicit_dest"]
            c6a_hits = match(events, c6_sport, c6a_dport, ("::1",))
            c6b_hits = match(events, c6_sport, c6b_dport, ("::1",))
            self.assertEqual(
                len(c6a_hits), 2,
                "expected 2 IPv6 events targeting corked port A, got %r" % c6a_hits,
            )
            for hit in c6a_hits:
                self.assertEqual(hit["ip"], 6)
            self.assertEqual(
                len(c6b_hits), 0,
                "unexpected IPv6 event targeting ignored port B: %r" % c6b_hits,
            )


if __name__ == "__main__":
    main()

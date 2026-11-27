#!/usr/bin/env python3
# Licensed under the Apache License, Version 2.0 (the "License")

import contextlib
import os
import select
import signal
import socket
import struct
import subprocess
import sys
import time
from unittest import main, skipUnless, TestCase
from utils import kernel_version_ge

TOOLS_DIR = "/bcc/tools/"

if not os.path.exists("/bcc/tools/"):
    TOOLS_DIR = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "../../tools/"
    )

sys.path.insert(0, os.path.abspath(TOOLS_DIR))
import udpsend  # noqa: E402


def build_dns_query(qname, qtype=1, qclass=1, flags=0x0100, txid=0x1234, edns0=False):
    arcount = 1 if edns0 else 0
    pkt = bytearray(struct.pack("!HHHHHH", txid, flags, 1, 0, 0, arcount))
    if qname and qname != ".":
        for label in qname.strip(".").split("."):
            raw = label.encode("ascii")
            pkt.append(len(raw))
            pkt.extend(raw)
    pkt.append(0)
    pkt.extend(struct.pack("!HH", qtype, qclass))
    if edns0:
        # Root name (0), TYPE=OPT (41), UDP payload size (1232), ext RCODE/flags (0), RDLEN (0)
        pkt.extend(struct.pack("!BHHIH", 0, 41, 1232, 0, 0))
    return bytes(pkt)


def has_ipv6_loopback():
    if not socket.has_ipv6:
        return False
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.bind(("::1", 0))
            return True
    except OSError:
        return False


def parse_event_line(line, with_dns=False):
    parts = line.split(None, 9) if with_dns else line.split()
    expected_len = 10 if with_dns else 9
    if len(parts) != expected_len:
        return None
    try:
        ev = {
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
        if with_dns:
            ev["dns"] = parts[9]
        return ev
    except ValueError:
        return None


class UdpsendDnsParserTests(TestCase):
    def test_valid_queries(self):
        self.assertEqual(
            udpsend.parse_dns_query(build_dns_query("example.com", qtype=1)),
            "query example.com A",
        )
        self.assertEqual(
            udpsend.parse_dns_query(build_dns_query("example.com", qtype=28, flags=0x0120)),
            "query example.com AAAA",
        )
        self.assertEqual(
            udpsend.parse_dns_query(build_dns_query(".", qtype=2)),
            "query . NS",
        )
        self.assertEqual(
            udpsend.parse_dns_query(build_dns_query("svc.example.org", qtype=65, edns0=True)),
            "query svc.example.org HTTPS",
        )
        # mDNS unicast-response bit (0x8001)
        self.assertEqual(
            udpsend.parse_dns_query(build_dns_query("_http._tcp.local", qtype=12, qclass=0x8001)),
            "query _http._tcp.local PTR",
        )
        self.assertEqual(
            udpsend.parse_dns_query(build_dns_query("custom.example", qtype=999)),
            "query custom.example TYPE999",
        )
        # > 512-byte EDNS0 query whose question + OPT header fit in the 256B prefix
        padded_opt = struct.pack("!BHHIH", 0, 41, 1232, 0, 480) + b"\x00" * 480
        base_q = build_dns_query("padded.example.com", qtype=28)
        long_edns = base_q[:10] + struct.pack("!H", 1) + base_q[12:] + padded_opt
        self.assertGreater(len(long_edns), 512)
        self.assertEqual(
            udpsend.parse_dns_query(long_edns[:256], msg_len=len(long_edns)),
            "query padded.example.com AAAA",
        )
        # Escaping '.' and '\\' preserves original label boundaries
        esc_q = (
            struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
            + b"\x08lab.node\x07example\x00"
            + struct.pack("!HH", 1, 1)
        )
        self.assertEqual(
            udpsend.parse_dns_query(esc_q),
            r"query lab\.node.example A",
        )

    def test_reject_non_queries_and_malformed(self):
        # Plain non-DNS payload
        self.assertIsNone(udpsend.parse_dns_query(b"hello world udp payload"))
        # DNS response (QR=1)
        self.assertIsNone(
            udpsend.parse_dns_query(build_dns_query("example.com", flags=0x8180))
        )
        # Trailing garbage when ARCOUNT=0
        self.assertIsNone(
            udpsend.parse_dns_query(build_dns_query("example.com") + b"\x00")
        )
        # Truncated message where msg_len > captured length with ARCOUNT=0
        pkt = build_dns_query("example.com")
        self.assertIsNone(udpsend.parse_dns_query(pkt, msg_len=len(pkt) + 4))
        # Compression pointer in Q1
        bad_ptr = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c\x00\x01\x00\x01"
        self.assertIsNone(udpsend.parse_dns_query(bad_ptr))
        # Non-printable byte in label
        bad_lbl = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x03a\x01b\x00\x00\x01\x00\x01"
        self.assertIsNone(udpsend.parse_dns_query(bad_lbl))
        # Invalid additional record when ARCOUNT=1 (not OPT/TSIG/SIG)
        bad_ar = build_dns_query("example.com")[:-4] + struct.pack("!HH", 1, 1) + b"\x00\x00\x01" + b"\x00" * 8
        bad_ar = bad_ar[:10] + struct.pack("!H", 1) + bad_ar[12:]
        self.assertIsNone(udpsend.parse_dns_query(bad_ar))
        # Missing additional record when ARCOUNT=1 (packet ends right after Question)
        missing_ar1 = pkt[:10] + struct.pack("!H", 1) + pkt[12:]
        self.assertIsNone(udpsend.parse_dns_query(missing_ar1))
        # Missing second additional record when ARCOUNT=2 (only 1 OPT present)
        one_opt = build_dns_query("example.com", edns0=True)
        missing_ar2 = one_opt[:10] + struct.pack("!H", 2) + one_opt[12:]
        self.assertIsNone(udpsend.parse_dns_query(missing_ar2))
        # Two OPT records (forbidden by RFC 6891)
        opt_rr = struct.pack("!BHHIH", 0, 41, 1232, 0, 0)
        two_opts = one_opt[:10] + struct.pack("!H", 2) + one_opt[12:] + opt_rr
        self.assertIsNone(udpsend.parse_dns_query(two_opts))
        # Out-of-bounds compression pointer in Additional RR
        bad_ar_ptr = (
            pkt[:10] + struct.pack("!H", 1) + pkt[12:]
            + struct.pack("!HHHIH", 0xc0ff, 250, 255, 0, 0)
        )
        self.assertIsNone(udpsend.parse_dns_query(bad_ar_ptr))
        # Compression pointer landing inside an existing QNAME label (offset 13)
        mid_label_ptr = (
            pkt[:10] + struct.pack("!H", 1) + pkt[12:]
            + struct.pack("!HHHIH", 0xc00d, 250, 255, 0, 0)
        )
        self.assertIsNone(udpsend.parse_dns_query(mid_label_ptr))
        # Self-referential compression pointer targeting current RR's own label
        self_ptr_offset = len(pkt)
        self_loop_ptr = (
            pkt[:10] + struct.pack("!H", 1) + pkt[12:]
            + b"\x01a" + struct.pack("!HHHIH", 0xc000 | self_ptr_offset, 250, 255, 0, 0)
        )
        self.assertIsNone(udpsend.parse_dns_query(self_loop_ptr))

    def test_parse_ports(self):
        self.assertEqual(udpsend.parse_ports("53"), [53])
        self.assertEqual(udpsend.parse_ports("53, 5353, 53"), [53, 5353])
        for bad in ("", "0", "65536", "-1", "abc", "53,", ",53", "53,,80"):
            with self.assertRaises(ValueError):
                udpsend.parse_ports(bad)


@skipUnless(kernel_version_ge(4, 10), "requires kernel >= 4.10")
class UdpsendToolTests(TestCase):
    def _run_udpsend_and_capture(self, send_fn, done_fn, extra_args=()):
        with_dns = ("--dns" in extra_args) or ("-d" in extra_args)
        proc = subprocess.Popen(
            [TOOLS_DIR + "udpsend.py", "-t"] + list(extra_args),
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
                ev = parse_event_line(line, with_dns=with_dns)
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

    @skipUnless(kernel_version_ge(4, 18), "requires kernel >= 4.18 for --dns")
    def test_dns_flag_loopback(self):
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
            if len(match(events, *info["v4_a"], ("127.0.0.1",))) < 1:
                return False
            if len(match(events, *info["v4_edns"], ("127.0.0.1",))) < 1:
                return False
            if len(match(events, *info["v4_nondns"], ("127.0.0.1",))) < 1:
                return False
            if ipv6_ok:
                if len(match(events, *info["v6_aaaa"], ("::1",))) < 1:
                    return False
                if len(match(events, *info["v4mapped_txt"], v4_addrs)) < 1:
                    return False
            return True

        def send_probes():
            info = {}
            with contextlib.ExitStack() as stack:
                # 1. IPv4 standard DNS query (non-53 ephemeral port)
                rx1 = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                tx1 = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                rx1.bind(("127.0.0.1", 0))
                d1 = rx1.getsockname()[1]
                tx1.sendto(build_dns_query("example.com", qtype=1), ("127.0.0.1", d1))
                info["v4_a"] = (tx1.getsockname()[1], d1)

                # 2. IPv4 DNS query with EDNS0 OPT record
                rx2 = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                tx2 = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                rx2.bind(("127.0.0.1", 0))
                d2 = rx2.getsockname()[1]
                tx2.sendto(
                    build_dns_query("edns.example.org", qtype=28, edns0=True),
                    ("127.0.0.1", d2),
                )
                info["v4_edns"] = (tx2.getsockname()[1], d2)

                # 3. IPv4 non-DNS UDP payload
                rx3 = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                tx3 = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                rx3.bind(("127.0.0.1", 0))
                d3 = rx3.getsockname()[1]
                tx3.sendto(b"not-a-dns-packet", ("127.0.0.1", d3))
                info["v4_nondns"] = (tx3.getsockname()[1], d3)

                if ipv6_ok:
                    # 4. Native IPv6 DNS query
                    rx4 = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
                    tx4 = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
                    rx4.bind(("::1", 0))
                    d4 = rx4.getsockname()[1]
                    tx4.sendto(build_dns_query("v6.example.com", qtype=28), ("::1", d4))
                    info["v6_aaaa"] = (tx4.getsockname()[1], d4)

                    # 5. Dual-stack IPv4-mapped DNS query
                    rx5 = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                    tx5 = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
                    rx5.bind(("127.0.0.1", 0))
                    d5 = rx5.getsockname()[1]
                    tx5.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                    tx5.sendto(
                        build_dns_query("mapped.example.com", qtype=16),
                        ("::ffff:127.0.0.1", d5),
                    )
                    info["v4mapped_txt"] = (tx5.getsockname()[1], d5)

            return info

        events, err, info = self._run_udpsend_and_capture(
            send_probes, all_expected_seen, extra_args=("--dns",)
        )

        h1 = match(events, *info["v4_a"], ("127.0.0.1",))
        self.assertEqual(len(h1), 1, "expected 1 IPv4 A query event, got %r" % h1)
        self.assertEqual(h1[0]["dns"], "query example.com A")

        h2 = match(events, *info["v4_edns"], ("127.0.0.1",))
        self.assertEqual(len(h2), 1, "expected 1 IPv4 EDNS0 query event, got %r" % h2)
        self.assertEqual(h2[0]["dns"], "query edns.example.org AAAA")

        h3 = match(events, *info["v4_nondns"], ("127.0.0.1",))
        self.assertEqual(len(h3), 1, "expected 1 non-DNS IPv4 event, got %r" % h3)
        self.assertEqual(h3[0]["dns"], "-")

        if ipv6_ok:
            self.assertNotIn("tracing IPv4 only", err)
            h4 = match(events, *info["v6_aaaa"], ("::1",))
            self.assertEqual(len(h4), 1, "expected 1 IPv6 AAAA query event, got %r" % h4)
            self.assertEqual(h4[0]["ip"], 6)
            self.assertEqual(h4[0]["dns"], "query v6.example.com AAAA")

            h5 = match(events, *info["v4mapped_txt"], v4_addrs)
            self.assertEqual(len(h5), 1, "expected 1 deduplicated mapped TXT event, got %r" % h5)
            self.assertEqual(h5[0]["ip"], 4)
            self.assertEqual(h5[0]["daddr"], "127.0.0.1")
            self.assertEqual(h5[0]["dns"], "query mapped.example.com TXT")

    def test_port_filter_loopback(self):
        ipv6_ok = has_ipv6_loopback()
        my_pid = os.getpid()

        def match(events, sport, dport, daddrs):
            return [
                e for e in events
                if e["pid"] == my_pid
                and e["sport"] == sport
                and e["dport"] == dport
                and e["daddr"] in daddrs
            ]

        with contextlib.ExitStack() as stack:
            rx_allow4 = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            rx_drop4 = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            rx_allow4.bind(("127.0.0.1", 0))
            rx_drop4.bind(("127.0.0.1", 0))
            p_allow4 = rx_allow4.getsockname()[1]
            p_drop4 = rx_drop4.getsockname()[1]
            filter_ports = [p_allow4]

            p_allow6 = None
            p_drop6 = None
            if ipv6_ok:
                rx_allow6 = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
                rx_drop6 = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
                rx_allow6.bind(("::1", 0))
                rx_drop6.bind(("::1", 0))
                p_allow6 = rx_allow6.getsockname()[1]
                p_drop6 = rx_drop6.getsockname()[1]
                if p_allow6 not in filter_ports:
                    filter_ports.append(p_allow6)

            def all_expected_seen(events, info):
                if len(match(events, *info["allow4"], ("127.0.0.1",))) < 1:
                    return False
                if ipv6_ok and len(match(events, *info["allow6"], ("::1",))) < 1:
                    return False
                return True

            def send_probes():
                info = {}
                with contextlib.ExitStack() as tx_stack:
                    tx_d4 = tx_stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                    tx_d4.sendto(b"drop4", ("127.0.0.1", p_drop4))
                    info["drop4"] = (tx_d4.getsockname()[1], p_drop4)

                    tx_a4 = tx_stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                    tx_a4.sendto(b"allow4", ("127.0.0.1", p_allow4))
                    info["allow4"] = (tx_a4.getsockname()[1], p_allow4)

                    if ipv6_ok:
                        tx_d6 = tx_stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
                        tx_d6.sendto(b"drop6", ("::1", p_drop6))
                        info["drop6"] = (tx_d6.getsockname()[1], p_drop6)

                        tx_a6 = tx_stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
                        tx_a6.sendto(b"allow6", ("::1", p_allow6))
                        info["allow6"] = (tx_a6.getsockname()[1], p_allow6)
                return info

            port_arg = ",".join(str(p) for p in filter_ports)
            events, err, info = self._run_udpsend_and_capture(
                send_probes, all_expected_seen, extra_args=("-P", port_arg)
            )

        self.assertEqual(len(match(events, *info["allow4"], ("127.0.0.1",))), 1)
        if p_drop4 not in filter_ports:
            self.assertEqual(len(match(events, *info["drop4"], ("127.0.0.1",))), 0)
        if ipv6_ok:
            self.assertNotIn("tracing IPv4 only", err)
            self.assertEqual(len(match(events, *info["allow6"], ("::1",))), 1)
            if p_drop6 not in filter_ports:
                self.assertEqual(len(match(events, *info["drop6"], ("::1",))), 0)


if __name__ == "__main__":
    main()

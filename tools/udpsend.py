#!/usr/bin/env python3
# coding:utf-8
#
# udpsend    Trace UDP sendmsg()s.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: udpsend [-h] [-T] [-t]
#
# Traces sendmsg() calls that reach udp_sendmsg() or udpv6_sendmsg(), including
# failed calls.
#
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Jan-2024   Zhixiong Wei   Created this.

import argparse
import os
from socket import inet_ntop, AF_INET, AF_INET6, ntohs
from struct import pack
import sys
from time import monotonic, strftime
from bcc import BPF
from bcc.utils import printb

# arguments
examples = """examples:
    ./udpsend           # trace all UDP sendmsg()s
    ./udpsend -t        # include seconds since trace start
    ./udpsend -T        # include wall-clock time (HH:MM:SS)
"""
parser = argparse.ArgumentParser(
    description="Trace UDP sends",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--time", action="store_true",
    help="include wall-clock time column when event is read (HH:MM:SS)")
parser.add_argument("-t", "--timestamp", action="store_true",
    help="include seconds since trace start")
args = parser.parse_args()


# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <linux/udp.h>
#include <uapi/linux/in.h>

struct ipv4_data_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u64 ip;
    u16 sport;
    u16 dport;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);

#if IS_ENABLED(CONFIG_IPV6)
#include <uapi/linux/in6.h>

struct ipv6_data_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ip;
    u16 sport;
    u16 dport;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_events);

struct ipv6_call_t {
    struct ipv6_data_t event;
    u64 sock_addr;
    u64 msg_addr;
};

struct ipv6_stats_t {
    u64 store_failures;
    u64 unreturned;
    u64 evicted;
};

// Keep one pending call per thread until return or forwarding to udp_sendmsg().
// Use an LRU hash (Linux >= 4.10) so orphaned entries from missed kretprobes
// are automatically evicted by the kernel without needing a global thread-exit
// probe or userspace table scans.
BPF_TABLE("lru_hash", u64, struct ipv6_call_t, v6_pending, 10240);
BPF_ARRAY(v6_stats, struct ipv6_stats_t, 1);

static __always_inline void discard_unreturned_ipv6(u64 pid_tgid) {
    if (v6_pending.delete(&pid_tgid) != 0)
        return;

    u32 zero = 0;
    struct ipv6_stats_t *stats = v6_stats.lookup(&zero);
    if (stats)
        __sync_fetch_and_add(&stats->unreturned, 1);
}
#endif

// IPv4 path. udp_sendmsg() is also the function udpv6_sendmsg() forwards to for
// v4 / v4-mapped / IPv4-corked sends on dual-stack sockets, so this is where
// those get reported.
//
// Note: For normal userspace sends, inet_sendmsg() runs inet_autobind() before
// calling udp_sendmsg(), so SPORT (skc_num) is already assigned even on a
// socket's first send. For unbound, unconnected sockets, SADDR (skc_rcv_saddr)
// remains 0.0.0.0 on every send because the kernel does not write the
// route-selected source address back into the socket.
int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
#if IS_ENABLED(CONFIG_IPV6)
    // udpv6_sendmsg() forwards with the same socket and msghdr, even when it
    // changes msg_name. An unrelated send on this thread must keep the event.
    struct ipv6_call_t *call = v6_pending.lookup(&pid_tgid);
    if (call && call->sock_addr == (u64)sk && call->msg_addr == (u64)msg)
        v6_pending.delete(&pid_tgid);
#endif
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid();

    struct ipv4_data_t data4;
    __builtin_memset(&data4, 0, sizeof(data4));
    data4.pid = pid;
    data4.uid = uid;
    data4.ip = 4;
    data4.ts_us = bpf_ktime_get_ns() / 1000;
    bpf_probe_read_kernel(&data4.saddr, sizeof(data4.saddr),
        &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&data4.sport, sizeof(data4.sport),
        &sk->__sk_common.skc_num);

    struct udp_sock *up = (struct udp_sock *)sk;
    int pending = 0;
    bpf_probe_read_kernel(&pending, sizeof(pending), &up->pending);

    if (pending == AF_INET) {
        // Corked send (UDP_CORK / MSG_MORE): destination is saved in cork.fl.
        bpf_probe_read_kernel(&data4.daddr, sizeof(data4.daddr),
            &up->inet.cork.fl.u.ip4.daddr);
        bpf_probe_read_kernel(&data4.dport, sizeof(data4.dport),
            &up->inet.cork.fl.u.ip4.uli.ports.dport);
    } else {
        // A sendto() destination overrides the connected peer (UDP allows
        // sendto() on an already-connected socket), so msg->msg_name takes
        // priority. Validate msg_namelen and sa_family (udp_sendmsg() permits
        // AF_INET and AF_UNSPEC).
        void *msg_name = NULL;
        int msg_namelen = 0;
        bpf_probe_read_kernel(&msg_name, sizeof(msg_name), &msg->msg_name);
        bpf_probe_read_kernel(&msg_namelen, sizeof(msg_namelen), &msg->msg_namelen);

        u16 sa_family = 0xffff;
        if (msg_name != NULL && msg_namelen >= (int)sizeof(struct sockaddr_in))
            bpf_probe_read_kernel(&sa_family, sizeof(sa_family), msg_name);

        if (sa_family == AF_INET || sa_family == AF_UNSPEC) {
            struct sockaddr_in sin = {};
            bpf_probe_read_kernel(&sin, sizeof(sin), msg_name);
            data4.daddr = sin.sin_addr.s_addr;
            data4.dport = sin.sin_port;
        } else {
            // no (decodable) explicit destination: fall back to the connected peer
            bpf_probe_read_kernel(&data4.daddr, sizeof(data4.daddr),
                &sk->__sk_common.skc_daddr);
            bpf_probe_read_kernel(&data4.dport, sizeof(data4.dport),
                &sk->__sk_common.skc_dport);
        }
    }

    bpf_get_current_comm(&data4.task, sizeof(data4.task));
    ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    return 0;
}

#if IS_ENABLED(CONFIG_IPV6)
// IPv6 path. Attached manually to udpv6_sendmsg() entry + return (see Python side).
int trace_udpv6_sendmsg(struct pt_regs *ctx, struct sock *sk,
                        struct msghdr *msg) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    // A leftover record belongs to a call whose return probe did not run.
    discard_unreturned_ipv6(pid_tgid);

    struct ipv6_call_t call;
    __builtin_memset(&call, 0, sizeof(call));
    call.sock_addr = (u64)sk;
    call.msg_addr = (u64)msg;
    struct ipv6_data_t *data6 = &call.event;
    data6->pid = pid_tgid >> 32;
    data6->uid = bpf_get_current_uid_gid();
    data6->ip = 6;
    data6->ts_us = bpf_ktime_get_ns() / 1000;
    bpf_probe_read_kernel(&data6->saddr, sizeof(data6->saddr),
        &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    bpf_probe_read_kernel(&data6->sport, sizeof(data6->sport),
        &sk->__sk_common.skc_num);

    struct udp_sock *up = (struct udp_sock *)sk;
    int pending = 0;
    bpf_probe_read_kernel(&pending, sizeof(pending), &up->pending);

    void *msg_name = NULL;
    int msg_namelen = 0;
    bpf_probe_read_kernel(&msg_name, sizeof(msg_name), &msg->msg_name);
    bpf_probe_read_kernel(&msg_namelen, sizeof(msg_namelen), &msg->msg_namelen);

    bool use_cork_or_peer = false;
    if (msg_name != NULL) {
        if (msg_namelen >= (int)sizeof(u16)) {
            u16 sa_family = 0xffff;
            bpf_probe_read_kernel(&sa_family, sizeof(sa_family), msg_name);
            if (sa_family == AF_INET6 &&
                msg_namelen >=
                    (int)offsetof(struct sockaddr_in6, sin6_scope_id)) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)msg_name;
                u32 daddr[4] = {};
                bpf_probe_read_kernel(&daddr, sizeof(daddr), &sin6->sin6_addr);
                if (pending == AF_INET6 &&
                    !(daddr[0] == 0 && daddr[1] == 0 &&
                      daddr[2] == bpf_htonl(0x0000ffff))) {
                    // Kernel appends native IPv6 sends to the existing corked
                    // IPv6 flow rather than switching to the new destination.
                    use_cork_or_peer = true;
                } else {
                    __builtin_memcpy(&data6->daddr, daddr, sizeof(data6->daddr));
                    bpf_probe_read_kernel(&data6->dport, sizeof(data6->dport),
                        &sin6->sin6_port);
                }
            } else if (sa_family == AF_INET &&
                       msg_namelen >= (int)sizeof(struct sockaddr_in)) {
                // Only emitted if udp_sendmsg() is NOT invoked (e.g. IPV6_V6ONLY).
                struct sockaddr_in sin = {};
                bpf_probe_read_kernel(&sin, sizeof(sin), msg_name);
                u32 mapped[4] = {0, 0, bpf_htonl(0x0000ffff), sin.sin_addr.s_addr};
                __builtin_memcpy(&data6->daddr, mapped, sizeof(data6->daddr));
                data6->dport = sin.sin_port;
            } else if (sa_family == AF_UNSPEC) {
                use_cork_or_peer = true;
            }
        }
    } else {
        use_cork_or_peer = true;
    }

    if (use_cork_or_peer) {
        if (pending == AF_INET6) {
            bpf_probe_read_kernel(&data6->daddr, sizeof(data6->daddr),
                &up->inet.cork.fl.u.ip6.daddr.in6_u.u6_addr32);
            bpf_probe_read_kernel(&data6->dport, sizeof(data6->dport),
                &up->inet.cork.fl.u.ip6.uli.ports.dport);
        } else {
            bpf_probe_read_kernel(&data6->daddr, sizeof(data6->daddr),
                &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
            bpf_probe_read_kernel(&data6->dport, sizeof(data6->dport),
                &sk->__sk_common.skc_dport);
        }
    }

    bpf_get_current_comm(&data6->task, sizeof(data6->task));
    if (v6_pending.update(&pid_tgid, &call) != 0) {
        u32 zero = 0;
        struct ipv6_stats_t *stats = v6_stats.lookup(&zero);
        if (stats)
            __sync_fetch_and_add(&stats->store_failures, 1);
    }
    return 0;
}

int trace_udpv6_sendmsg_ret(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ipv6_call_t *call = v6_pending.lookup(&pid_tgid);
    if (!call)
        return 0;

    // Copy to the BPF stack, then confirm the key was still present via
    // delete() before submitting. LRU eviction unlinks the key before reusing
    // node storage, so a successful delete() guarantees the copied event was
    // not overwritten by another thread.
    struct ipv6_data_t data6;
    __builtin_memcpy(&data6, &call->event, sizeof(data6));
    if (v6_pending.delete(&pid_tgid) != 0) {
        u32 zero = 0;
        struct ipv6_stats_t *stats = v6_stats.lookup(&zero);
        if (stats)
            __sync_fetch_and_add(&stats->evicted, 1);
        return 0;
    }
    ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    return 0;
}
#endif
"""


def root_monotonic_us():
    # Align userspace CLOCK_MONOTONIC with bpf_ktime_get_ns() (root time
    # namespace) by removing any time-namespace monotonic offset.
    ts_us = int(monotonic() * 1000000)
    try:
        with open("/proc/self/timens_offsets") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and parts[0] == "monotonic":
                    ts_us -= int(parts[1]) * 1000000 + int(parts[2]) // 1000
                    break
    except OSError:
        pass
    return ts_us


def print_event(event, saddr, daddr):
    if args.time:
        printb(b"%-9s" % strftime("%H:%M:%S").encode('ascii'), nl="")
    if args.timestamp:
        delta_s = max(0.0, (float(event.ts_us) - start_ts) / 1000000)
        printb(b"%-9.3f" % delta_s, nl="")
    printb(b"%-7d %-7d %-12.12s %-2d %-16s %-5d %-16s %-5d" % (event.pid,
        event.uid, event.task, event.ip, saddr, event.sport, daddr,
        ntohs(event.dport)))


def print_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)
    print_event(event,
        inet_ntop(AF_INET, pack("I", event.saddr)).encode(),
        inet_ntop(AF_INET, pack("I", event.daddr)).encode())


def print_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)
    print_event(event,
        inet_ntop(AF_INET6, event.saddr).encode(),
        inet_ntop(AF_INET6, event.daddr).encode())


def report_ipv6_stats(table, previous):
    current = table[0]
    store_failures = current.store_failures - previous.store_failures
    unreturned = current.unreturned - previous.unreturned
    evicted = current.evicted - previous.evicted
    if store_failures:
        print("WARNING: could not store %d pending IPv6 calls" % store_failures,
              file=sys.stderr)
    if unreturned:
        print("WARNING: discarded %d pending IPv6 calls without an observed return"
              % unreturned, file=sys.stderr)
    if evicted:
        print("WARNING: lost %d pending IPv6 calls due to LRU eviction"
              % evicted, file=sys.stderr)
    return current


# Record trace start time before attaching probes so -t offsets are relative to
# trace start and never negative across CPUs or perf buffers.
start_ts = root_monotonic_us()

# initialize BPF
# kprobe__udp_sendmsg is auto-attached to udp_sendmsg (IPv4 path). The IPv6 path
# (udpv6_sendmsg) is optional. Install the return probe before the entry probe
# so every stored call has an active return hook.
b = BPF(text=bpf_text)
has_ipv6 = False
kretprobe_attached = False
maxactive = max(128, (os.cpu_count() or 1) * 4)
try:
    try:
        b.attach_kretprobe(event="udpv6_sendmsg",
                           fn_name="trace_udpv6_sendmsg_ret",
                           maxactive=maxactive)
    except Exception:
        b.attach_kretprobe(event="udpv6_sendmsg",
                           fn_name="trace_udpv6_sendmsg_ret")
    kretprobe_attached = True
    b.attach_kprobe(event="udpv6_sendmsg", fn_name="trace_udpv6_sendmsg")
    has_ipv6 = True
except Exception as error:
    if kretprobe_attached:
        try:
            b.detach_kretprobe("udpv6_sendmsg")
        except Exception:
            pass
    print("WARNING: could not attach IPv6 probes; tracing IPv4 only (%s)"
          % error, file=sys.stderr)

# Open perf buffers before printing the header so callers waiting on the header
# know event capture is fully ready.
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
if has_ipv6:
    b["ipv6_events"].open_perf_buffer(print_ipv6_event)
    ipv6_stats = b["v6_stats"]
    previous_ipv6_stats = ipv6_stats.Leaf()
    next_ipv6_report = monotonic() + 5.0

print("Tracing UDP sendmsg ... Hit Ctrl-C to end")

if args.time:
    print("%-9s" % ("TIME"), end="")
if args.timestamp:
    print("%-9s" % ("TIME(s)"), end="")
# header
print("%-7s %-7s %-12s %-2s %-16s %-5s %-16s %-5s" % ("PID", "UID", "COMM",
    "IP", "SADDR", "SPORT", "DADDR", "DPORT"), flush=True)

# read events
try:
    while True:
        b.perf_buffer_poll(timeout=1000 if has_ipv6 else -1)
        if has_ipv6:
            now = monotonic()
            if now >= next_ipv6_report:
                previous_ipv6_stats = report_ipv6_stats(ipv6_stats, previous_ipv6_stats)
                next_ipv6_report = now + 5.0
except KeyboardInterrupt:
    if has_ipv6:
        report_ipv6_stats(ipv6_stats, previous_ipv6_stats)

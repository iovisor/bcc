#!/usr/bin/env python3
# coding:utf-8
#
# udpsend    Trace UDP sendmsg()s.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: udpsend [-h] [-t]
#
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Jan-2024   Zhixiong Wei   Created this.

from bcc import BPF
from bcc.utils import printb
from socket import inet_ntop, AF_INET, AF_INET6, ntohs
from struct import pack
import argparse
from time import strftime

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
    help="include time column on output (HH:MM:SS)")
parser.add_argument("-t", "--timestamp", action="store_true",
    help="include seconds since trace start")
args = parser.parse_args()


# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <uapi/linux/in.h>
#include <uapi/linux/in6.h>
#include <bcc/proto.h>

// separate data structs for ipv4 and ipv6
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

// IPv4 path. udp_sendmsg() is also the function udpv6_sendmsg() forwards to for
// v4 (and v4-mapped) destinations on dual-stack sockets, so this is where those
// get reported.
//
// Note: UDP autobind happens inside udp_sendmsg(), after this entry kprobe, so
// the source port (skc_num) may read as 0 on a socket's first send. This is an
// inherent limitation of probing at function entry.
int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 uid = bpf_get_current_uid_gid();

    struct ipv4_data_t data4 = {};
    __builtin_memset(&data4, 0, sizeof(data4));
    data4.pid = pid;
    data4.uid = uid;
    data4.ip = 4;
    data4.ts_us = bpf_ktime_get_ns() / 1000;
    data4.saddr = sk->__sk_common.skc_rcv_saddr;
    data4.sport = sk->__sk_common.skc_num;

    // A sendto() destination overrides the connected peer (UDP allows sendto()
    // on an already-connected socket), so msg->msg_name takes priority. Only
    // decode it when it actually carries an AF_INET address.
    void *msg_name = NULL;
    bpf_probe_read_kernel(&msg_name, sizeof(msg_name), &msg->msg_name);
    u16 sa_family = 0;
    if (msg_name != NULL)
        bpf_probe_read_kernel(&sa_family, sizeof(sa_family), msg_name);

    if (sa_family == AF_INET) {
        struct sockaddr_in sin = {};
        bpf_probe_read_kernel(&sin, sizeof(sin), msg_name);
        data4.daddr = sin.sin_addr.s_addr;
        data4.dport = sin.sin_port;
    } else {
        // no (decodable) explicit destination: fall back to the connected peer
        data4.daddr = sk->__sk_common.skc_daddr;
        bpf_probe_read_kernel(&data4.dport, sizeof(data4.dport),
            &sk->__sk_common.skc_dport);
    }

    bpf_get_current_comm(&data4.task, sizeof(data4.task));
    ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    return 0;
}

// IPv6 path. Attached manually to udpv6_sendmsg() (see Python side).
int trace_udpv6_sendmsg(struct pt_regs *ctx, struct sock *sk,
                        struct msghdr *msg) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 uid = bpf_get_current_uid_gid();

    void *msg_name = NULL;
    bpf_probe_read_kernel(&msg_name, sizeof(msg_name), &msg->msg_name);
    u16 sa_family = 0;
    if (msg_name != NULL)
        bpf_probe_read_kernel(&sa_family, sizeof(sa_family), msg_name);

    // A plain AF_INET destination on a dual-stack socket is forwarded by
    // udpv6_sendmsg() to udp_sendmsg(), where kprobe__udp_sendmsg reports it.
    // Drop it here to avoid a duplicate (and to avoid mis-decoding a
    // sockaddr_in as a sockaddr_in6).
    if (sa_family == AF_INET)
        return 0;

    struct ipv6_data_t data6 = {};
    __builtin_memset(&data6, 0, sizeof(data6));
    data6.pid = pid;
    data6.uid = uid;
    data6.ip = 6;
    data6.ts_us = bpf_ktime_get_ns() / 1000;
    bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr),
        &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    data6.sport = sk->__sk_common.skc_num;

    if (sa_family == AF_INET6) {
        struct sockaddr_in6 sin6 = {};
        bpf_probe_read_kernel(&sin6, sizeof(sin6), msg_name);
        bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr),
            &sin6.sin6_addr);
        data6.dport = sin6.sin6_port;
    } else {
        // no explicit destination: fall back to the connected peer
        bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr),
            &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data6.dport, sizeof(data6.dport),
            &sk->__sk_common.skc_dport);
    }

    bpf_get_current_comm(&data6.task, sizeof(data6.task));
    ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    return 0;
}
"""


def print_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)
    global start_ts
    if args.time:
        printb(b"%-9s" % strftime("%H:%M:%S").encode('ascii'), nl="")
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        printb(b"%-9.3f" % ((float(event.ts_us) - start_ts) / 1000000), nl="")
    printb(b"%-7d %-7d %-12.12s %-2d %-16s %-5d %-16s %-5d" % (event.pid,
        event.uid, event.task, event.ip,
        inet_ntop(AF_INET, pack("I", event.saddr)).encode(),
        event.sport,
        inet_ntop(AF_INET, pack("I", event.daddr)).encode(),
        ntohs(event.dport)))


def print_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)
    global start_ts
    if args.time:
        printb(b"%-9s" % strftime("%H:%M:%S").encode('ascii'), nl="")
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        printb(b"%-9.3f" % ((float(event.ts_us) - start_ts) / 1000000), nl="")
    printb(b"%-7d %-7d %-12.12s %-2d %-16s %-5d %-16s %-5d" % (event.pid,
        event.uid, event.task, event.ip,
        inet_ntop(AF_INET6, event.saddr).encode(),
        event.sport,
        inet_ntop(AF_INET6, event.daddr).encode(),
        ntohs(event.dport)))


# initialize BPF
b = BPF(text=bpf_text)
# kprobe__udp_sendmsg is auto-attached to udp_sendmsg (IPv4 path). The IPv6 path
# (udpv6_sendmsg) is attached manually and is optional: on kernels where the
# symbol is unavailable (e.g. CONFIG_IPV6=m and the module isn't loaded) we
# degrade gracefully to IPv4-only tracing.
try:
    b.attach_kprobe(event="udpv6_sendmsg", fn_name="trace_udpv6_sendmsg")
except Exception:
    print("WARNING: could not attach to udpv6_sendmsg; tracing IPv4 only")

print("Tracing UDP sendmsg ... Hit Ctrl-C to end")

if args.time:
    print("%-9s" % ("TIME"), end="")
if args.timestamp:
    print("%-9s" % ("TIME(s)"), end="")
# header
print("%-7s %-7s %-12s %-2s %-16s %-5s %-16s %-5s" % ("PID", "UID", "COMM",
    "IP", "SADDR", "SPORT", "DADDR", "DPORT"))

start_ts = 0

# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
b["ipv6_events"].open_perf_buffer(print_ipv6_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

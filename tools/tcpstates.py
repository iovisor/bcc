#!/usr/bin/python
# -*- coding: utf-8 -*-
# @lint-avoid-python-3-compatibility-imports
#
# tcpstates   Trace the TCP session state changes with durations.
#             For Linux, uses BCC, BPF. Embedded C.
#
# USAGE: tcpstates [-h] [-C] [-S] [interval [count]]
#
# This uses the sock:inet_sock_set_state tracepoint, added to Linux 4.16.
# Linux 4.16 also adds more state transitions so that they can be traced.
#
# Copyright 2018 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 20-Mar-2018   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
import argparse
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import strftime, time
from os import getuid

# arguments
examples = """examples:
    ./tcpstates           # trace all TCP state changes
    ./tcpstates -t        # include timestamp column
    ./tcpstates -T        # include time column (HH:MM:SS)
    ./tcpstates -w        # wider columns (fit IPv6)
    ./tcpstates -stT      # csv output, with times & timestamps
    ./tcpstates -Y        # log events to the systemd journal
    ./tcpstates -L 80     # only trace local port 80
    ./tcpstates -L 80,81  # only trace local ports 80 and 81
    ./tcpstates -D 80     # only trace remote port 80
"""
parser = argparse.ArgumentParser(
    description="Trace TCP session state changes and durations",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--time", action="store_true",
    help="include time column on output (HH:MM:SS)")
parser.add_argument("-t", "--timestamp", action="store_true",
    help="include timestamp on output (seconds)")
parser.add_argument("-w", "--wide", action="store_true",
    help="wide column output (fits IPv6 addresses)")
parser.add_argument("-s", "--csv", action="store_true",
    help="comma separated values output")
parser.add_argument("-L", "--localport",
    help="comma-separated list of local ports to trace.")
parser.add_argument("-D", "--remoteport",
    help="comma-separated list of remote ports to trace.")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
parser.add_argument("-Y", "--journal", action="store_true",
    help="log session state changes to the systemd journal")
args = parser.parse_args()
debug = 0

# define BPF program
bpf_header = """
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(last, struct sock *, u64);

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u64 ts_us;
    u64 skaddr;
    u32 saddr;
    u32 daddr;
    u64 span_us;
    u32 pid;
    u32 ports;
    u32 oldstate;
    u32 newstate;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u64 ts_us;
    u64 skaddr;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 span_us;
    u32 pid;
    u32 ports;
    u32 oldstate;
    u32 newstate;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_events);

struct id_t {
    u32 pid;
    char task[TASK_COMM_LEN];
};
"""
bpf_text_tracepoint = """
TRACEPOINT_PROBE(sock, inet_sock_set_state)
{
    if (args->protocol != IPPROTO_TCP)
        return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    // sk is used as a UUID
    struct sock *sk = (struct sock *)args->skaddr;

    // lport is either used in a filter here, or later
    u16 lport = args->sport;
    FILTER_LPORT

    // dport is either used in a filter here, or later
    u16 dport = args->dport;
    FILTER_DPORT

    // calculate delta
    u64 *tsp, delta_us;
    tsp = last.lookup(&sk);
    if (tsp == 0)
        delta_us = 0;
    else
        delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;

    if (args->family == AF_INET) {
        struct ipv4_data_t data4 = {
            .span_us = delta_us,
            .oldstate = args->oldstate,
            .newstate = args->newstate };
        data4.skaddr = (u64)args->skaddr;
        data4.ts_us = bpf_ktime_get_ns() / 1000;
        __builtin_memcpy(&data4.saddr, args->saddr, sizeof(data4.saddr));
        __builtin_memcpy(&data4.daddr, args->daddr, sizeof(data4.daddr));
        // a workaround until data4 compiles with separate lport/dport
        data4.ports = dport + ((0ULL + lport) << 16);
        data4.pid = pid;

        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        ipv4_events.perf_submit(args, &data4, sizeof(data4));

    } else /* 6 */ {
        struct ipv6_data_t data6 = {
            .span_us = delta_us,
            .oldstate = args->oldstate,
            .newstate = args->newstate };
        data6.skaddr = (u64)args->skaddr;
        data6.ts_us = bpf_ktime_get_ns() / 1000;
        __builtin_memcpy(&data6.saddr, args->saddr_v6, sizeof(data6.saddr));
        __builtin_memcpy(&data6.daddr, args->daddr_v6, sizeof(data6.daddr));
        // a workaround until data6 compiles with separate lport/dport
        data6.ports = dport + ((0ULL + lport) << 16);
        data6.pid = pid;
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        ipv6_events.perf_submit(args, &data6, sizeof(data6));
    }

    u64 ts = bpf_ktime_get_ns();
    last.update(&sk, &ts);

    return 0;
}
"""

bpf_text_kprobe = """
int kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state)
{
    // check this is TCP
    u8 protocol = 0;

    // Following comments add by Joe Yin:
    // Unfortunately,it can not work since Linux 4.10,
    // because the sk_wmem_queued is not following the bitfield of sk_protocol.
    // And the following member is sk_gso_max_segs.
    // So, we can use this:
    // bpf_probe_read_kernel(&protocol, 1, (void *)((u64)&newsk->sk_gso_max_segs) - 3);
    // In order to  diff the pre-4.10 and 4.10+ ,introduce the variables gso_max_segs_offset,sk_lingertime,
    // sk_lingertime is closed to the gso_max_segs_offset,and
    // the offset between the two members is 4

    int gso_max_segs_offset = offsetof(struct sock, sk_gso_max_segs);
    int sk_lingertime_offset = offsetof(struct sock, sk_lingertime);

    if (sk_lingertime_offset - gso_max_segs_offset == 4)
        // 4.10+ with little endian
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        bpf_probe_read_kernel(&protocol, 1, (void *)((u64)&sk->sk_gso_max_segs) - 3);
else
        // pre-4.10 with little endian
        bpf_probe_read_kernel(&protocol, 1, (void *)((u64)&sk->sk_wmem_queued) - 3);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        // 4.10+ with big endian
        bpf_probe_read_kernel(&protocol, 1, (void *)((u64)&sk->sk_gso_max_segs) - 1);
else
        // pre-4.10 with big endian
        bpf_probe_read_kernel(&protocol, 1, (void *)((u64)&sk->sk_wmem_queued) - 1);
#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif

    if (protocol != IPPROTO_TCP)
        return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    // sk is used as a UUID

    // lport is either used in a filter here, or later
    u16 lport = sk->__sk_common.skc_num;
    FILTER_LPORT

    // dport is either used in a filter here, or later
    u16 dport = sk->__sk_common.skc_dport;
    FILTER_DPORT

    // calculate delta
    u64 *tsp, delta_us;
    tsp = last.lookup(&sk);
    if (tsp == 0)
        delta_us = 0;
    else
        delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;

    u16 family = sk->__sk_common.skc_family;

    if (family == AF_INET) {
        struct ipv4_data_t data4 = {
            .span_us = delta_us,
            .oldstate = sk->__sk_common.skc_state,
            .newstate = state };
        data4.skaddr = (u64)sk;
        data4.ts_us = bpf_ktime_get_ns() / 1000;
        data4.saddr = sk->__sk_common.skc_rcv_saddr;
        data4.daddr = sk->__sk_common.skc_daddr;
        // a workaround until data4 compiles with separate lport/dport
        data4.ports = dport + ((0ULL + lport) << 16);
        data4.pid = pid;

        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));

    } else /* 6 */ {
        struct ipv6_data_t data6 = {
            .span_us = delta_us,
            .oldstate = sk->__sk_common.skc_state,
            .newstate = state };
        data6.skaddr = (u64)sk;
        data6.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr),
            sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr),
            sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        // a workaround until data6 compiles with separate lport/dport
        data6.ports = dport + ((0ULL + lport) << 16);
        data6.pid = pid;
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }

    u64 ts = bpf_ktime_get_ns();
    last.update(&sk, &ts);

    return 0;

};
"""

bpf_text = bpf_header
if (BPF.tracepoint_exists("sock", "inet_sock_set_state")):
    bpf_text += bpf_text_tracepoint
else:
    bpf_text += bpf_text_kprobe

# code substitutions
if args.remoteport:
    dports = [int(dport) for dport in args.remoteport.split(',')]
    dports_if = ' && '.join(['dport != %d' % dport for dport in dports])
    bpf_text = bpf_text.replace('FILTER_DPORT',
        'if (%s) { last.delete(&sk); return 0; }' % dports_if)
if args.localport:
    lports = [int(lport) for lport in args.localport.split(',')]
    lports_if = ' && '.join(['lport != %d' % lport for lport in lports])
    bpf_text = bpf_text.replace('FILTER_LPORT',
        'if (%s) { last.delete(&sk); return 0; }' % lports_if)
bpf_text = bpf_text.replace('FILTER_DPORT', '')
bpf_text = bpf_text.replace('FILTER_LPORT', '')

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

#
# Setup output formats
#
# Don't change the default output (next 2 lines): this fits in 80 chars. I
# know it doesn't have NS or UIDs etc. I know. If you really, really, really
# need to add columns, columns that solve real actual problems, I'd start by
# adding an extended mode (-x) to included those columns.
#
header_string = "%-16s %-5s %-10.10s %s%-15s %-5s %-15s %-5s %-11s -> %-11s %s"
format_string = ("%-16x %-5d %-10.10s %s%-15s %-5d %-15s %-5d %-11s " +
    "-> %-11s %.3f")
if args.wide:
    header_string = ("%-16s %-5s %-16.16s %-2s %-26s %-5s %-26s %-5s %-11s " +
        "-> %-11s %s")
    format_string = ("%-16x %-5d %-16.16s %-2s %-26s %-5s %-26s %-5d %-11s " +
        "-> %-11s %.3f")
if args.csv:
    header_string = "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s"
    format_string = "%x,%d,%s,%s,%s,%s,%s,%d,%s,%s,%.3f"

if args.journal:
    try:
        from systemd import journal
    except ImportError:
        print("ERROR: Journal logging requires the systemd.journal module")
        exit(1)


def tcpstate2str(state):
    # from include/net/tcp_states.h:
    tcpstate = {
        1: "ESTABLISHED",
        2: "SYN_SENT",
        3: "SYN_RECV",
        4: "FIN_WAIT1",
        5: "FIN_WAIT2",
        6: "TIME_WAIT",
        7: "CLOSE",
        8: "CLOSE_WAIT",
        9: "LAST_ACK",
        10: "LISTEN",
        11: "CLOSING",
        12: "NEW_SYN_RECV",
    }

    if state in tcpstate:
        return tcpstate[state]
    else:
        return str(state)

def journal_fields(event, addr_family):
    addr_pfx = 'IPV4'
    if addr_family == AF_INET6:
        addr_pfx = 'IPV6'

    fields = {
        # Standard fields described in systemd.journal-fields(7). journal.send
        # will fill in CODE_LINE, CODE_FILE, and CODE_FUNC for us. If we're
        # root and specify OBJECT_PID, systemd-journald will add other OBJECT_*
        # fields for us.
        'SYSLOG_IDENTIFIER': 'tcpstates',
        'PRIORITY': 5,
        '_SOURCE_REALTIME_TIMESTAMP': time() * 1000000,
        'OBJECT_PID': str(event.pid),
        'OBJECT_COMM': event.task.decode('utf-8', 'replace'),
        # Custom fields, aka "stuff we sort of made up".
        'OBJECT_' + addr_pfx + '_SOURCE_ADDRESS': inet_ntop(addr_family, pack("I", event.saddr)),
        'OBJECT_TCP_SOURCE_PORT': str(event.ports >> 16),
        'OBJECT_' + addr_pfx + '_DESTINATION_ADDRESS': inet_ntop(addr_family, pack("I", event.daddr)),
        'OBJECT_TCP_DESTINATION_PORT': str(event.ports & 0xffff),
        'OBJECT_TCP_OLD_STATE': tcpstate2str(event.oldstate),
        'OBJECT_TCP_NEW_STATE': tcpstate2str(event.newstate),
        'OBJECT_TCP_SPAN_TIME': str(event.span_us)
        }

    msg_format_string = (u"%(OBJECT_COMM)s " +
        u"%(OBJECT_" + addr_pfx + "_SOURCE_ADDRESS)s " +
        u"%(OBJECT_TCP_SOURCE_PORT)s → " +
        u"%(OBJECT_" + addr_pfx + "_DESTINATION_ADDRESS)s " +
        u"%(OBJECT_TCP_DESTINATION_PORT)s " +
        u"%(OBJECT_TCP_OLD_STATE)s → %(OBJECT_TCP_NEW_STATE)s")
    fields['MESSAGE'] = msg_format_string % (fields)

    if getuid() == 0:
        del fields['OBJECT_COMM'] # Handled by systemd-journald

    return fields

# process event
def print_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)
    global start_ts
    if args.time:
        if args.csv:
            print("%s," % strftime("%H:%M:%S"), end="")
        else:
            print("%-8s " % strftime("%H:%M:%S"), end="")
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        delta_s = (float(event.ts_us) - start_ts) / 1000000
        if args.csv:
            print("%.6f," % delta_s, end="")
        else:
            print("%-9.6f " % delta_s, end="")
    print(format_string % (event.skaddr, event.pid, event.task.decode('utf-8', 'replace'),
        "4" if args.wide or args.csv else "",
        inet_ntop(AF_INET, pack("I", event.saddr)), event.ports >> 16,
        inet_ntop(AF_INET, pack("I", event.daddr)), event.ports & 0xffff,
        tcpstate2str(event.oldstate), tcpstate2str(event.newstate),
        float(event.span_us) / 1000))
    if args.journal:
        journal.send(**journal_fields(event, AF_INET))

def print_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)
    global start_ts
    if args.time:
        if args.csv:
            print("%s," % strftime("%H:%M:%S"), end="")
        else:
            print("%-8s " % strftime("%H:%M:%S"), end="")
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        delta_s = (float(event.ts_us) - start_ts) / 1000000
        if args.csv:
            print("%.6f," % delta_s, end="")
        else:
            print("%-9.6f " % delta_s, end="")
    print(format_string % (event.skaddr, event.pid, event.task.decode('utf-8', 'replace'),
        "6" if args.wide or args.csv else "",
        inet_ntop(AF_INET6, event.saddr), event.ports >> 16,
        inet_ntop(AF_INET6, event.daddr), event.ports & 0xffff,
        tcpstate2str(event.oldstate), tcpstate2str(event.newstate),
        float(event.span_us) / 1000))
    if args.journal:
        journal.send(**journal_fields(event, AF_INET6))

# initialize BPF
b = BPF(text=bpf_text)

# header
if args.time:
    if args.csv:
        print("%s," % ("TIME"), end="")
    else:
        print("%-8s " % ("TIME"), end="")
if args.timestamp:
    if args.csv:
        print("%s," % ("TIME(s)"), end="")
    else:
        print("%-9s " % ("TIME(s)"), end="")
print(header_string % ("SKADDR", "C-PID", "C-COMM",
    "IP" if args.wide or args.csv else "",
    "LADDR", "LPORT", "RADDR", "RPORT",
    "OLDSTATE", "NEWSTATE", "MS"))

start_ts = 0

# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event, page_cnt=64)
b["ipv6_events"].open_perf_buffer(print_ipv6_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

#!/usr/bin/python
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
import ctypes as ct
from time import strftime

# arguments
examples = """examples:
    ./tcpstates           # trace all TCP state changes
    ./tcpstates -t        # include timestamp column
    ./tcpstates -T        # include time column (HH:MM:SS)
    ./tcpstates -w        # wider colums (fit IPv6)
    ./tcpstates -stT      # csv output, with times & timestamps
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
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#define KBUILD_MODNAME "foo"
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
        data4.ports = dport + ((0ULL + lport) << 32);
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
        data6.ports = dport + ((0ULL + lport) << 32);
        data6.pid = pid;
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        ipv6_events.perf_submit(args, &data6, sizeof(data6));
    }

    u64 ts = bpf_ktime_get_ns();
    last.update(&sk, &ts);

    return 0;
}
"""

if (not BPF.tracepoint_exists("sock", "inet_sock_set_state")):
    print("ERROR: tracepoint sock:inet_sock_set_state missing "
        "(added in Linux 4.16). Exiting")
    exit()

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

# event data
TASK_COMM_LEN = 16      # linux/sched.h

class Data_ipv4(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("skaddr", ct.c_ulonglong),
        ("saddr", ct.c_uint),
        ("daddr", ct.c_uint),
        ("span_us", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("ports", ct.c_uint),
        ("oldstate", ct.c_uint),
        ("newstate", ct.c_uint),
        ("task", ct.c_char * TASK_COMM_LEN)
    ]

class Data_ipv6(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("skaddr", ct.c_ulonglong),
        ("saddr", (ct.c_ulonglong * 2)),
        ("daddr", (ct.c_ulonglong * 2)),
        ("span_us", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("ports", ct.c_uint),
        ("oldstate", ct.c_uint),
        ("newstate", ct.c_uint),
        ("task", ct.c_char * TASK_COMM_LEN)
    ]

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

# process event
def print_ipv4_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv4)).contents
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
        inet_ntop(AF_INET, pack("I", event.saddr)), event.ports >> 32,
        inet_ntop(AF_INET, pack("I", event.daddr)), event.ports & 0xffffffff,
        tcpstate2str(event.oldstate), tcpstate2str(event.newstate),
        float(event.span_us) / 1000))

def print_ipv6_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv6)).contents
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
        inet_ntop(AF_INET6, event.saddr), event.ports >> 32,
        inet_ntop(AF_INET6, event.daddr), event.ports & 0xffffffff,
        tcpstate2str(event.oldstate), tcpstate2str(event.newstate),
        float(event.span_us) / 1000))

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
    b.perf_buffer_poll()

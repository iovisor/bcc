#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# tcpconnect    Trace TCP connect()s.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpconnect [-h] [-t] [-p PID]
#
# All connection attempts are traced, even if they ultimately fail.
#
# This uses dynamic tracing of kernel functions, and will need to be updated
# to match kernel changes.
#
# IPv4 addresses are printed as dotted quads. For IPv6 addresses, the last four
# bytes are printed after "..."; check for future versions with better IPv6
# support.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 25-Sep-2015   Brendan Gregg   Created this.
# 14-Feb-2016      "      "     Switch to bpf_perf_output.

from __future__ import print_function
from bcc import BPF
import argparse
import re
from struct import pack, unpack_from
import ctypes as ct

# arguments
examples = """examples:
    ./tcpconnect           # trace all TCP connect()s
    ./tcpconnect -t        # include timestamps
    ./tcpconnect -p 181    # only trace PID 181
"""
parser = argparse.ArgumentParser(
    description="Trace TCP connects",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-t", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(currsock, u32, struct sock *);

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    // XXX: switch some to u32's when supported
    u64 ts_us;
    u64 pid;
    u64 ip;
    u64 saddr;
    u64 daddr;
    u64 dport;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u64 ts_us;
    u64 pid;
    u64 ip;
    u64 saddr[2];
    u64 daddr[2];
    u64 dport;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_events);

int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    u32 pid = bpf_get_current_pid_tgid();
    FILTER

    // stash the sock ptr for lookup on return
    currsock.update(&pid, &sk);

    return 0;
};

static int trace_connect_return(struct pt_regs *ctx, short ipver)
{
    int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid();

    struct sock **skpp;
    skpp = currsock.lookup(&pid);
    if (skpp == 0) {
        return 0;   // missed entry
    }

    if (ret != 0) {
        // failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        currsock.delete(&pid);
        return 0;
    }

    // pull in details
    struct sock *skp = *skpp;
    u16 dport = 0;
    bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);

    if (ipver == 4) {
        struct ipv4_data_t data4 = {.pid = pid, .ip = ipver};
        data4.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_probe_read(&data4.saddr, sizeof(u32),
            &skp->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&data4.daddr, sizeof(u32),
            &skp->__sk_common.skc_daddr);
        data4.dport = ntohs(dport);
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));

    } else /* 6 */ {
        struct ipv6_data_t data6 = {.pid = pid, .ip = ipver};
        data6.ts_us = bpf_ktime_get_ns() / 1000;
        // just grab the last 4 bytes for now
        bpf_probe_read(&data6.saddr[0], sizeof(data6.saddr[0]),
            &skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[0]);
        bpf_probe_read(&data6.saddr[1], sizeof(data6.saddr[1]),
            &skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[2]);
        bpf_probe_read(&data6.daddr[0], sizeof(data6.daddr[0]),
            &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32[0]);
        bpf_probe_read(&data6.daddr[1], sizeof(data6.daddr[1]),
            &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32[2]);
        data6.dport = ntohs(dport);
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }

    currsock.delete(&pid);

    return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 4);
}

int trace_connect_v6_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 6);
}
"""

# code substitutions
if args.pid:
    bpf_text = bpf_text.replace('FILTER',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '')
if debug:
    print(bpf_text)

# event data
TASK_COMM_LEN = 16      # linux/sched.h
class Data_ipv4(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("pid", ct.c_ulonglong),
        ("ip", ct.c_ulonglong),
        ("saddr", ct.c_ulonglong),
        ("daddr", ct.c_ulonglong),
        ("dport", ct.c_ulonglong),
        ("task", ct.c_char * TASK_COMM_LEN)
    ]
class Data_ipv6(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("pid", ct.c_ulonglong),
        ("ip", ct.c_ulonglong),
        ("saddr", ct.c_ulonglong * 2),
        ("daddr", ct.c_ulonglong * 2),
        ("dport", ct.c_ulonglong),
        ("task", ct.c_char * TASK_COMM_LEN)
    ]

# process event
def print_ipv4_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv4)).contents
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        print("%-9.3f" % ((event.ts_us - start_ts) / 100000), end="")
    print("%-6d %-12.12s %-2d %-16s %-16s %-4d" % (event.pid, event.task,
        event.ip, inet_ntoa(event.saddr), inet_ntoa(event.daddr),
        event.dport))

def print_ipv6_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv6)).contents
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        print("%-9.3f" % ((event.ts_us - start_ts) / 100000), end="")
    print("%-6d %-12.12s %-2d %-16s %-16s %-4d" % (event.pid,
        event.task, event.ip,
        inet6_ntoa(event.saddr[1] << 64 | event.saddr[0]),
        inet6_ntoa(event.daddr[1] << 64 | event.daddr[0]),
        event.dport))

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect_entry")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_return")

# header
if args.timestamp:
    print("%-9s" % ("TIME(s)"), end="")
print("%-6s %-12s %-2s %-16s %-16s %-4s" % ("PID", "COMM", "IP", "SADDR",
    "DADDR", "DPORT"))

start_ts = 0

def inet_ntoa(addr):
    # u32 to dotted quad string
    dq = ''
    for i in range(0, 4):
        dq = dq + str(addr & 0xff)
        if (i != 3):
            dq = dq + '.'
        addr = addr >> 8
    return dq

def inet6_ntoa(addr):
    # see RFC4291 summary in RFC5952 section 2
    s = ":".join(["%x" % x for x in unpack_from(">HHHHHHHH",
        pack("QQ", addr & 0xffffffff, addr >> 64))])

    # compress left-most zero run only (change to most for RFC5952):
    s = re.sub(r'(^|:)0:(0:)+', r'::', s, 1)
    return s

# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
b["ipv6_events"].open_perf_buffer(print_ipv6_event)
while 1:
    b.kprobe_poll()

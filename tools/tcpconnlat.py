#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# tcpconnlat    Trace TCP active connection latency (connect).
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpconnlat [-h] [-t] [-p PID]
#
# This uses dynamic tracing of kernel functions, and will need to be updated
# to match kernel changes.
#
# IPv4 addresses are printed as dotted quads. For IPv6 addresses, the last four
# bytes are printed after "..."; check for future versions with better IPv6
# support.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 19-Feb-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
import argparse
import ctypes as ct

# arguments
examples = """examples:
    ./tcpconnlat           # trace all TCP connect()s
    ./tcpconnlat -t        # include timestamps
    ./tcpconnlat -p 181    # only trace PID 181
"""
parser = argparse.ArgumentParser(
    description="Trace TCP connects and show connection latency",
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

struct info_t {
    u64 ts;
    u64 pid;
    char task[TASK_COMM_LEN];
};
BPF_HASH(start, struct sock *, struct info_t);

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    // XXX: switch some to u32's when supported
    u64 ts_us;
    u64 pid;
    u64 ip;
    u64 saddr;
    u64 daddr;
    u64 dport;
    u64 delta_us;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    // XXX: update to transfer full ipv6 addrs
    u64 ts_us;
    u64 pid;
    u64 ip;
    u64 saddr;
    u64 daddr;
    u64 dport;
    u64 delta_us;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_events);

int trace_connect(struct pt_regs *ctx, struct sock *sk)
{
    u32 pid = bpf_get_current_pid_tgid();
    FILTER
    struct info_t info = {.pid = pid};
    info.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&info.task, sizeof(info.task));
    start.update(&sk, &info);
    return 0;
};

// See tcp_v4_do_rcv() and tcp_v6_do_rcv(). So TCP_ESTBALISHED and TCP_LISTEN
// are fast path and processed elsewhere, and leftovers are processed by
// tcp_rcv_state_process(). We can trace this for handshake completion.
// This should all be switched to static tracepoints when available.
int trace_tcp_rcv_state_process(struct pt_regs *ctx, struct sock *sk)
{
    // will be in TCP_SYN_SENT for handshake
    if (sk->__sk_common.skc_state != TCP_SYN_SENT)
        return 0;

    // check start and calculate delta
    struct info_t *infop = start.lookup(&sk);
    if (infop == 0) {
        return 0;   // missed entry or filtered
    }
    u64 ts = infop->ts;
    u64 now = bpf_ktime_get_ns();

    // pull in details
    u16 family = 0, dport = 0;
    struct sock *skp = NULL;
    bpf_probe_read(&skp, sizeof(skp), &sk);
    bpf_probe_read(&family, sizeof(family), &skp->__sk_common.skc_family);
    bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);

    // emit to appropriate data path
    if (family == AF_INET) {
        struct ipv4_data_t data4 = {.pid = infop->pid, .ip = 4};
        data4.ts_us = now / 1000;
        bpf_probe_read(&data4.saddr, sizeof(u32),
            &skp->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&data4.daddr, sizeof(u32),
            &skp->__sk_common.skc_daddr);
        data4.dport = ntohs(dport);
        data4.delta_us = (now - ts) / 1000;
        __builtin_memcpy(&data4.task, infop->task, sizeof(data4.task));
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));

    } else /* AF_INET6 */ {
        struct ipv6_data_t data6 = {.pid = infop->pid, .ip = 6};
        data6.ts_us = now / 1000;
        // just grab the last 4 bytes for now
        u32 saddr = 0, daddr = 0;
        bpf_probe_read(&saddr, sizeof(saddr),
            &skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[3]);
        bpf_probe_read(&daddr, sizeof(daddr),
            &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32[3]);
        data6.saddr = bpf_ntohl(saddr);
        data6.daddr = bpf_ntohl(daddr);
        data6.dport = ntohs(dport);
        data6.delta_us = (now - ts) / 1000;
        __builtin_memcpy(&data6.task, infop->task, sizeof(data6.task));
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }

    start.delete(&sk);

    return 0;
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

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect")
b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect")
b.attach_kprobe(event="tcp_rcv_state_process",
    fn_name="trace_tcp_rcv_state_process")

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
        ("delta_us", ct.c_ulonglong),
        ("task", ct.c_char * TASK_COMM_LEN)
    ]
class Data_ipv6(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("pid", ct.c_ulonglong),
        ("ip", ct.c_ulonglong),
        ("saddr", ct.c_ulonglong),
        ("daddr", ct.c_ulonglong),
        ("dport", ct.c_ulonglong),
        ("delta_us", ct.c_ulonglong),
        ("task", ct.c_char * TASK_COMM_LEN)
    ]

# functions
def inet_ntoa(addr):
    dq = ''
    for i in range(0, 4):
        dq = dq + str(addr & 0xff)
        if (i != 3):
            dq = dq + '.'
        addr = addr >> 8
    return dq

# process event
start_ts = 0
def print_ipv4_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv4)).contents
    global start_ts
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        print("%-9.3f" % ((event.ts_us - start_ts) / 100000), end="")
    print("%-6d %-12.12s %-2d %-16s %-16s %-5d %.2f" % (event.pid, event.task,
        event.ip, inet_ntoa(event.saddr), inet_ntoa(event.daddr),
        event.dport, float(event.delta_us) / 1000))
def print_ipv6_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv6)).contents
    global start_ts
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        print("%-9.3f" % ((event.ts_us - start_ts) / 100000), end="")
    print("%-6d %-12.12s %-2d ...%-13x ...%-13x %-5d %.2f" % (event.pid,
        event.task, event.ip, event.saddr, event.daddr, event.dport,
        float(event.delta_us) / 1000))

# header
if args.timestamp:
    print("%-9s" % ("TIME(s)"), end="")
print("%-6s %-12s %-2s %-16s %-16s %-5s %s" % ("PID", "COMM", "IP", "SADDR",
    "DADDR", "DPORT", "LAT(ms)"))

# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
b["ipv6_events"].open_perf_buffer(print_ipv6_event)
while 1:
    b.kprobe_poll()

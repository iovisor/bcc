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
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 19-Feb-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
import argparse
import ctypes as ct

# arg validation
def positive_float(val):
    try:
        ival = float(val)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a float")

    if ival < 0:
        raise argparse.ArgumentTypeError("must be positive")
    return ival

# arguments
examples = """examples:
    ./tcpconnlat           # trace all TCP connect()s
    ./tcpconnlat 1         # trace connection latency slower than 1 ms
    ./tcpconnlat 0.1       # trace connection latency slower than 100 us
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
parser.add_argument("duration_ms", nargs="?", default=0,
    type=positive_float,
    help="minimum duration to trace (ms)")
parser.add_argument("-v", "--verbose", action="store_true",
    help="print the BPF program for debugging purposes")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

if args.duration_ms:
    # support fractions but round to nearest microsecond
    duration_us = int(args.duration_ms * 1000)
else:
    duration_us = 0   # default is show all

debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <bcc/proto.h>

struct info_t {
    u64 ts;
    u32 pid;
    char task[TASK_COMM_LEN];
};
BPF_HASH(start, struct sock *, struct info_t);

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u64 ts_us;
    u32 pid;
    u32 saddr;
    u32 daddr;
    u64 ip;
    u16 dport;
    u64 delta_us;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u64 ts_us;
    u32 pid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ip;
    u16 dport;
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
int trace_tcp_rcv_state_process(struct pt_regs *ctx, struct sock *skp)
{
    // will be in TCP_SYN_SENT for handshake
    if (skp->__sk_common.skc_state != TCP_SYN_SENT)
        return 0;

    // check start and calculate delta
    struct info_t *infop = start.lookup(&skp);
    if (infop == 0) {
        return 0;   // missed entry or filtered
    }

    u64 ts = infop->ts;
    u64 now = bpf_ktime_get_ns();

    u64 delta_us = (now - ts) / 1000ul;

#ifdef MIN_LATENCY
    if ( delta_us < DURATION_US ) {
        return 0; // connect latency is below latency filter minimum
    }
#endif

    // pull in details
    u16 family = 0, dport = 0;
    family = skp->__sk_common.skc_family;
    dport = skp->__sk_common.skc_dport;

    // emit to appropriate data path
    if (family == AF_INET) {
        struct ipv4_data_t data4 = {.pid = infop->pid, .ip = 4};
        data4.ts_us = now / 1000;
        data4.saddr = skp->__sk_common.skc_rcv_saddr;
        data4.daddr = skp->__sk_common.skc_daddr;
        data4.dport = ntohs(dport);
        data4.delta_us = delta_us;
        __builtin_memcpy(&data4.task, infop->task, sizeof(data4.task));
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));

    } else /* AF_INET6 */ {
        struct ipv6_data_t data6 = {.pid = infop->pid, .ip = 6};
        data6.ts_us = now / 1000;
        bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
            skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
            skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.dport = ntohs(dport);
        data6.delta_us = delta_us;
        __builtin_memcpy(&data6.task, infop->task, sizeof(data6.task));
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }

    start.delete(&skp);

    return 0;
}
"""

if duration_us > 0:
    bpf_text = "#define MIN_LATENCY\n" + bpf_text
    bpf_text = bpf_text.replace('DURATION_US', str(duration_us))

# code substitutions
if args.pid:
    bpf_text = bpf_text.replace('FILTER',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '')
if debug or args.verbose or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

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
        ("pid", ct.c_uint),
        ("saddr", ct.c_uint),
        ("daddr", ct.c_uint),
        ("ip", ct.c_ulonglong),
        ("dport", ct.c_ushort),
        ("delta_us", ct.c_ulonglong),
        ("task", ct.c_char * TASK_COMM_LEN)
    ]

class Data_ipv6(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("saddr", (ct.c_ulonglong * 2)),
        ("daddr", (ct.c_ulonglong * 2)),
        ("ip", ct.c_ulonglong),
        ("dport", ct.c_ushort),
        ("delta_us", ct.c_ulonglong),
        ("task", ct.c_char * TASK_COMM_LEN)
    ]

# process event
start_ts = 0

def print_ipv4_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv4)).contents
    global start_ts
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        print("%-9.3f" % ((float(event.ts_us) - start_ts) / 1000000), end="")
    print("%-6d %-12.12s %-2d %-16s %-16s %-5d %.2f" % (event.pid,
        event.task.decode('utf-8', 'replace'), event.ip,
        inet_ntop(AF_INET, pack("I", event.saddr)),
        inet_ntop(AF_INET, pack("I", event.daddr)), event.dport,
        float(event.delta_us) / 1000))

def print_ipv6_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv6)).contents
    global start_ts
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        print("%-9.3f" % ((float(event.ts_us) - start_ts) / 1000000), end="")
    print("%-6d %-12.12s %-2d %-16s %-16s %-5d %.2f" % (event.pid,
        event.task.decode('utf-8', 'replace'), event.ip,
        inet_ntop(AF_INET6, event.saddr), inet_ntop(AF_INET6, event.daddr),
        event.dport, float(event.delta_us) / 1000))

# header
if args.timestamp:
    print("%-9s" % ("TIME(s)"), end="")
print("%-6s %-12s %-2s %-16s %-16s %-5s %s" % ("PID", "COMM", "IP", "SADDR",
    "DADDR", "DPORT", "LAT(ms)"))

# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
b["ipv6_events"].open_perf_buffer(print_ipv6_event)
while 1:
    b.perf_buffer_poll()

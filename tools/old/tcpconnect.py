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
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 25-Sep-2015   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
import argparse

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
    u32 saddr = 0, daddr = 0;
    u16 dport = 0;
    dport = skp->__sk_common.skc_dport;
    if (ipver == 4) {
        saddr = skp->__sk_common.skc_rcv_saddr;
        daddr = skp->__sk_common.skc_daddr;

        // output
        bpf_trace_printk("4 %x %x %d\\n", saddr, daddr, ntohs(dport));
    } else /* 6 */ {
        // just grab the last 4 bytes for now
        bpf_probe_read(&saddr, sizeof(saddr),
            &skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[3]);
        bpf_probe_read(&daddr, sizeof(daddr),
            &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32[3]);

        // output and flip byte order of addresses
        bpf_trace_printk("6 %x %x %d\\n", bpf_ntohl(saddr),
            bpf_ntohl(daddr), ntohs(dport));
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
    dq = ''
    for i in range(0, 4):
        dq = dq + str(addr & 0xff)
        if (i != 3):
            dq = dq + '.'
        addr = addr >> 8
    return dq

# format output
while 1:
    (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    (ip_s, saddr_hs, daddr_hs, dport_s) = msg.split(" ")

    if args.timestamp:
        if start_ts == 0:
            start_ts = ts
        print("%-9.3f" % (ts - start_ts), end="")
    print("%-6d %-12.12s %-2s %-16s %-16s %-4s" % (pid, task, ip_s,
        inet_ntoa(int(saddr_hs, 16)) if ip_s == "4" else "..." + saddr_hs,
        inet_ntoa(int(daddr_hs, 16)) if ip_s == "4" else "..." + daddr_hs,
        dport_s))

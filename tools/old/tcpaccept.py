#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# tcpaccept Trace TCP accept()s.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpaccept [-h] [-t] [-p PID]
#
# This uses dynamic tracing of the kernel inet_csk_accept() socket function
# (from tcp_prot.accept), and will need to be modified to match kernel changes.
#
# IPv4 addresses are printed as dotted quads. For IPv6 addresses, the last four
# bytes are printed after "..."; check for future versions with better IPv6
# support.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Oct-2015   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
import argparse

# arguments
examples = """examples:
    ./tcpaccept           # trace all TCP accept()s
    ./tcpaccept -t        # include timestamps
    ./tcpaccept -p 181    # only trace PID 181
"""
parser = argparse.ArgumentParser(
    description="Trace TCP accepts",
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

int kretprobe__inet_csk_accept(struct pt_regs *ctx)
{
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid();

    if (newsk == NULL)
        return 0;

    // check this is TCP
    u8 protocol = 0;
    // workaround for reading the sk_protocol bitfield:
    bpf_probe_read(&protocol, 1, (void *)((long)&newsk->sk_wmem_queued) - 3);
    if (protocol != IPPROTO_TCP)
        return 0;

    // pull in details
    u16 family = 0, lport = 0;
    u32 saddr = 0, daddr = 0;
    bpf_probe_read(&family, sizeof(family), &newsk->__sk_common.skc_family);
    bpf_probe_read(&lport, sizeof(lport), &newsk->__sk_common.skc_num);
    if (family == AF_INET) {
        bpf_probe_read(&saddr, sizeof(saddr),
            &newsk->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&daddr, sizeof(daddr),
            &newsk->__sk_common.skc_daddr);

        // output
        bpf_trace_printk("4 %x %x %d\\n", daddr, saddr, lport);
    } else if (family == AF_INET6) {
        // just grab the last 4 bytes for now
        bpf_probe_read(&saddr, sizeof(saddr),
            &newsk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[3]);
        bpf_probe_read(&daddr, sizeof(daddr),
            &newsk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[3]);

        // output and flip byte order of addresses
        bpf_trace_printk("6 %x %x %d\\n", bpf_ntohl(daddr),
            bpf_ntohl(saddr), lport);
    }
    // else drop

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

# header
if args.timestamp:
    print("%-9s" % ("TIME(s)"), end="")
print("%-6s %-12s %-2s %-16s %-16s %-4s" % ("PID", "COMM", "IP", "RADDR",
    "LADDR", "LPORT"))

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
    (ip_s, raddr_hs, laddr_hs, lport_s) = msg.split(" ")

    if args.timestamp:
        if start_ts == 0:
            start_ts = ts
        print("%-9.3f" % (ts - start_ts), end="")
    print("%-6d %-12.12s %-2s %-16s %-16s %-4s" % (pid, task, ip_s,
        inet_ntoa(int(raddr_hs, 16)) if ip_s == "4" else "..." + raddr_hs,
        inet_ntoa(int(laddr_hs, 16)) if ip_s == "4" else "..." + laddr_hs,
        lport_s))

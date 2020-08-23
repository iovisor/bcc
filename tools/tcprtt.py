#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# tcprtt    Summarize TCP RTT as a histogram. For Linux, uses BCC, eBPF.
#
# USAGE: tcprtt [-h] [-T] [-D] [-m] [-i INTERVAL] [-d DURATION]
#           [-p SPORT] [-P DPORT] [-a SADDR] [-A DADDR]
#
# Copyright (c) 2020 zhenwei pi
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 23-AUG-2020  zhenwei pi  Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import socket, struct
import argparse

# arguments
examples = """examples:
    ./tcprtt            # summarize TCP RTT
    ./tcprtt -i 1 -d 10 # print 1 second summaries, 10 times
    ./tcprtt -m -T      # summarize in millisecond, and timestamps
    ./tcprtt -p         # filter for source port
    ./tcprtt -P         # filter for destination port
    ./tcprtt -a         # filter for source address
    ./tcprtt -A         # filter for destination address
    ./tcprtt -D         # show debug bpf text
"""
parser = argparse.ArgumentParser(
    description="Summarize TCP RTT as a histogram",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-i", "--interval",
    help="summary interval, seconds")
parser.add_argument("-d", "--duration", type=int, default=99999,
    help="total duration of trace, seconds")
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="millisecond histogram")
parser.add_argument("-p", "--sport",
    help="source port")
parser.add_argument("-P", "--dport",
    help="destination port")
parser.add_argument("-a", "--saddr",
    help="source address")
parser.add_argument("-A", "--daddr",
    help="destination address")
parser.add_argument("-D", "--debug", action="store_true",
    help="print BPF program before starting (for debugging purposes)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
if not args.interval:
    args.interval = args.duration

# define BPF program
bpf_text = """
#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "bcc"
#endif
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>

BPF_HISTOGRAM(hist_srtt);

int trace_tcp_rcv(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb)
{
    struct tcp_sock *ts = tcp_sk(sk);
    u32 srtt = ts->srtt_us >> 3;
    const struct inet_sock *inet = inet_sk(sk);

    SPORTFILTER
    DPORTFILTER
    SADDRFILTER
    DADDRFILTER
    FACTOR

    hist_srtt.increment(bpf_log2l(srtt));

    return 0;
}
"""

# filter for source port
if args.sport:
    bpf_text = bpf_text.replace(b'SPORTFILTER',
        b"""u16 sport = 0;
    bpf_probe_read_kernel(&sport, sizeof(sport), (void *)&inet->inet_sport);
    if (ntohs(sport) != %d)
        return 0;""" % int(args.sport))
else:
    bpf_text = bpf_text.replace(b'SPORTFILTER', b'')

# filter for dest port
if args.dport:
    bpf_text = bpf_text.replace(b'DPORTFILTER',
        b"""u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), (void *)&inet->inet_dport);
    if (ntohs(dport) != %d)
        return 0;""" % int(args.dport))
else:
    bpf_text = bpf_text.replace(b'DPORTFILTER', b'')

# filter for source address
if args.saddr:
    bpf_text = bpf_text.replace(b'SADDRFILTER',
        b"""u32 saddr = 0;
    bpf_probe_read_kernel(&saddr, sizeof(saddr), (void *)&inet->inet_saddr);
    if (saddr != %d)
        return 0;""" % struct.unpack("=I", socket.inet_aton(args.saddr))[0])
else:
    bpf_text = bpf_text.replace(b'SADDRFILTER', b'')

# filter for source address
if args.daddr:
    bpf_text = bpf_text.replace(b'DADDRFILTER',
        b"""u32 daddr = 0;
    bpf_probe_read_kernel(&daddr, sizeof(daddr), (void *)&inet->inet_daddr);
    if (daddr != %d)
        return 0;""" % struct.unpack("=I", socket.inet_aton(args.daddr))[0])
else:
    bpf_text = bpf_text.replace(b'DADDRFILTER', b'')

# show msecs or usecs[default]
if args.milliseconds:
    bpf_text = bpf_text.replace('FACTOR', 'srtt /= 1000;')
    label = "msecs"
else:
    bpf_text = bpf_text.replace('FACTOR', '')
    label = "usecs"

# debug/dump ebpf enable or not
if args.debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# load BPF program
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_rcv_established", fn_name="trace_tcp_rcv")

print("Tracing TCP RTT... Hit Ctrl-C to end.")

# output
exiting = 0 if args.interval else 1
dist = b.get_table("hist_srtt")
seconds = 0
while (1):
    try:
        sleep(int(args.interval))
        seconds = seconds + int(args.interval)
    except KeyboardInterrupt:
        exiting = 1

    print()
    if args.timestamp:
        print("%-8s\n" % strftime("%H:%M:%S"), end="")

    dist.print_log2_hist(label, "srtt")
    dist.clear()

    if exiting or seconds >= args.duration:
        exit()

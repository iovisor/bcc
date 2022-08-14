#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# tcpsynbl      Show TCP SYN backlog.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpsynbl [-4 | -6] [-h]
#
# Copyright (c) 2019 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License").
# This was originally created for the BPF Performance Tools book
# published by Addison Wesley. ISBN-13: 9780136554820
# When copying or porting, include this comment.
#
# 03-Jul-2019   Brendan Gregg   Ported from bpftrace to BCC.

from __future__ import print_function
import argparse
from bcc import BPF
from time import sleep

# load BPF program
bpf_text = """
#include <net/sock.h>

typedef struct backlog_key {
    u32 backlog;
    u64 slot;
} backlog_key_t;

BPF_HISTOGRAM(dist, backlog_key_t);

int do_entry(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    
    backlog_key_t key = {};
    key.backlog = sk->sk_max_ack_backlog;
    key.slot = bpf_log2l(sk->sk_ack_backlog);
    dist.atomic_increment(key);

    return 0;
};
"""
examples = """examples:
    ./tcpsynbl          # trace syn backlog
    ./tcpsynbl -4       # trace IPv4 family only
    ./tcpsynbl -6       # trace IPv6 family only
"""
parser = argparse.ArgumentParser(
    description="Show TCP SYN backlog.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
group = parser.add_mutually_exclusive_group()
group.add_argument("-4", "--ipv4", action="store_true",
    help="trace IPv4 family only")
group.add_argument("-6", "--ipv6", action="store_true",
    help="trace IPv6 family only")
args = parser.parse_args()

b = BPF(text=bpf_text)

if args.ipv4:
    b.attach_kprobe(event="tcp_v4_syn_recv_sock", fn_name="do_entry")
elif args.ipv6:
    b.attach_kprobe(event="tcp_v6_syn_recv_sock", fn_name="do_entry")
else:
    b.attach_kprobe(event="tcp_v4_syn_recv_sock", fn_name="do_entry")
    b.attach_kprobe(event="tcp_v6_syn_recv_sock", fn_name="do_entry")

print("Tracing SYN backlog size. Ctrl-C to end.");

try:
    sleep(99999999)
except KeyboardInterrupt:
    print()

dist = b.get_table("dist")
dist.print_log2_hist("backlog", "backlog_max")

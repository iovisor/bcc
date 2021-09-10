#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# swapin        Count swapins by process.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# TODO: add -s for total swapin time column (sum)
#
# Copyright (c) 2019 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License").
# This was originally created for the BPF Performance Tools book
# published by Addison Wesley. ISBN-13: 9780136554820
# When copying or porting, include this comment.
#
# 03-Jul-2019   Brendan Gregg   Ported from bpftrace to BCC.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse

# arguments
parser = argparse.ArgumentParser(
    description="Count swapin events by process.")
parser.add_argument("-T", "--notime", action="store_true",
    help="do not show the timestamp (HH:MM:SS)")
parser.add_argument("interval", nargs="?", default=1,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
interval = int(args.interval)
countdown = int(args.count)
debug = 0

# load BPF program
b = BPF(text="""
#include <linux/sched.h>

struct key_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(counts, struct key_t, u64);

int kprobe__swap_readpage(struct pt_regs *ctx)
{
    u64 *val, zero = 0;
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct key_t key = {.pid = tgid};
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    val = counts.lookup_or_init(&key, &zero);
    ++(*val);
    return 0;
}
""")
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

print("Counting swap ins. Ctrl-C to end.");

# output
exiting = 0
while 1:
    try:
        sleep(interval)
    except KeyboardInterrupt:
        exiting = 1

    if not args.notime:
        print(strftime("%H:%M:%S"))
    print("%-16s %-6s %s" % ("COMM", "PID", "COUNT"))
    counts = b.get_table("counts")
    for k, v in sorted(counts.items(),
		       key=lambda counts: counts[1].value):
        print("%-16s %-6d %d" % (k.comm, k.pid, v.value))
    counts.clear()
    print()

    countdown -= 1
    if exiting or countdown == 0:
        print("Detaching...")
        exit()

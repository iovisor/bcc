#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# swapin        Count swapins by process.
#               For Linux, uses BCC, eBPF. Embedded C.
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
parser.add_argument("-s", "--sum", action="store_true",
    help="print time spent swap in / swap out per PID")
parser.add_argument("-o", "--swapout", action="store_true",
    help="print time spent swap out per PID")
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

bpf_text = ""

# enable time measurement
if args.sum:
    bpf_text += """
#define TIMING 1
"""
# enable swap out
if args.swapout:
    bpf_text += """
#define SWAPOUT 1
"""

# load BPF program
bpf_text += """
#include <linux/sched.h>

struct key_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};

struct value_t {
    u32 count_in;
    u64 startTime_in;
    u64 time_in; // cumulated time spent in swap_readpage()
#ifdef SWAPOUT
    u32 count_out;
    u64 startTime_out;
    u64 time_out; // cumulated time spent in swap_writepage()
#endif
};

// counts is a map aka key/value storage
BPF_HASH(counts, struct key_t, struct value_t);

int kprobe__swap_readpage(struct pt_regs *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    struct value_t valZero = {0,0,0};
    struct value_t *val;
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct key_t key = {.pid = tgid};
    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    val = counts.lookup_or_init(&key, &valZero);
    if(!val)
        return 0;

    val->count_in++;
    val->startTime_in = ts;

    counts.update(&key, val);

    return 0;
}

#ifdef SWAPOUT
int kprobe__swap_writepage(struct pt_regs *ctx)
{
    u64 stime = bpf_ktime_get_ns();
    struct value_t valZero = {0,0,0};
    struct value_t *val;
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct key_t key = {.pid = tgid};
    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    val = counts.lookup_or_init(&key, &valZero);
    if(!val)
        return 0;

    val->count_out++;
    val->startTime_out = stime;

    // update the map
    counts.update(&key, val);

    return 0;
}
#endif // SWAPOUT
#ifdef TIMING
int kretprobe__swap_readpage(struct pt_regs *ctx)
{
    u64 endTime = bpf_ktime_get_ns();
    struct key_t key = {};
    struct value_t *val;

    bpf_get_current_comm(key.comm, sizeof(key.comm));
    key.pid = bpf_get_current_pid_tgid();
    val=counts.lookup(&key);
    if(!val || val->startTime_in == 0)
        return 0;

    val->time_in += endTime - val->startTime_in;
    // now update the map
    counts.update(&key, val);

    return 0;
}
#ifdef SWAPOUT
int kretprobe__swap_writepage(struct pt_regs *ctx)
{
    u64 endTime = bpf_ktime_get_ns();
    struct key_t key = {};
    struct value_t *val;

    bpf_get_current_comm(key.comm, sizeof(key.comm));
    key.pid = bpf_get_current_pid_tgid();
    val=counts.lookup(&key);
    if(!val || val->startTime_out == 0)
        return 0;

    val->time_out += endTime - val->startTime_out;
    // now update the map
    counts.update(&key, val);

    return 0;
}
#endif // SWAPOUT
#endif // TIMING
"""
b = BPF(text=bpf_text)


def _sort_by_count(count):
    cnt = count[1].count_in
    if args.swapout:
        cnt += count[1].count_out

    return cnt

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

print("Counting swap activities. Ctrl-C to end.")

# output
exiting = 0

header_line = "%-20s %-7s | %7s " % ("COMM", "PID", "SI_CNT")
if args.sum:
    header_line += "%10s " % ("TIME(ms)")
if args.swapout:
    header_line += "| %7s " % ("SO_CNT")
    if args.sum:
        header_line += "%10s " % ("TIME(ms)")

while 1:
    try:
        sleep(interval)
    except KeyboardInterrupt:
        exiting = 1

    if not args.notime:
        print(strftime("%H:%M:%S"))

    print(header_line)
    counts = b.get_table("counts")
    for k, v in sorted(counts.items(), key=_sort_by_count):
        line = "%-20s %-7d | %7d " % (k.comm, k.pid, v.count_in)
        if args.sum:
            line += "%10.2f " % (float(v.time_in) / 1000000)
        if args.swapout:
            line += "| %7d " % v.count_out
            if args.sum:
                line += "%10.2f " % (float(v.time_out) / 1000000)
        print(line)
    counts.clear()
    print()

    countdown -= 1
    if exiting or countdown == 0:
        print("Detaching...")
        exit()

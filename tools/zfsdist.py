#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# zfsdist  Summarize ZFS operation latency.
#          For Linux, uses BCC, eBPF.
#
# USAGE: zfsdist [-h] [-T] [-m] [-p PID] [interval] [count]
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Feb-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse

# arguments
examples = """examples:
    ./zfsdist            # show operation latency as a histogram
    ./zfsdist -p 181     # trace PID 181 only
    ./zfsdist 1 10       # print 1 second summaries, 10 times
    ./zfsdist -m 5       # 5s summaries, milliseconds
"""
parser = argparse.ArgumentParser(
    description="Summarize ZFS operation latency",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--notimestamp", action="store_true",
    help="don't include timestamp on interval output")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="output in milliseconds")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("interval", nargs="?",
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
pid = args.pid
countdown = int(args.count)
if args.milliseconds:
    factor = 1000000
    label = "msecs"
else:
    factor = 1000
    label = "usecs"
if args.interval and int(args.interval) == 0:
    print("ERROR: interval 0. Exiting.")
    exit()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

#define OP_NAME_LEN 8
typedef struct dist_key {
    char op[OP_NAME_LEN];
    u64 slot;
} dist_key_t;
BPF_HASH(start, u32);
BPF_HISTOGRAM(dist, dist_key_t);

// time operation
int trace_entry(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    if (FILTER_PID)
        return 0;
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    return 0;
}

static int trace_return(struct pt_regs *ctx, const char *op)
{
    u64 *tsp;
    u32 pid = bpf_get_current_pid_tgid();

    // fetch timestamp and calculate delta
    tsp = start.lookup(&pid);
    if (tsp == 0) {
        return 0;   // missed start or filtered
    }
    u64 delta = (bpf_ktime_get_ns() - *tsp) / FACTOR;

    // store as histogram
    dist_key_t key = {.slot = bpf_log2l(delta)};
    __builtin_memcpy(&key.op, op, sizeof(key.op));
    dist.increment(key);

    start.delete(&pid);
    return 0;
}

int trace_read_return(struct pt_regs *ctx)
{
    char *op = "read";
    return trace_return(ctx, op);
}

int trace_write_return(struct pt_regs *ctx)
{
    char *op = "write";
    return trace_return(ctx, op);
}

int trace_open_return(struct pt_regs *ctx)
{
    char *op = "open";
    return trace_return(ctx, op);
}

int trace_fsync_return(struct pt_regs *ctx)
{
    char *op = "fsync";
    return trace_return(ctx, op);
}
"""
bpf_text = bpf_text.replace('FACTOR', str(factor))
if args.pid:
    bpf_text = bpf_text.replace('FILTER_PID', 'pid != %s' % pid)
else:
    bpf_text = bpf_text.replace('FILTER_PID', '0')
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# load BPF program
b = BPF(text=bpf_text)

# common file functions
if BPF.get_kprobe_functions(b'zpl_iter'):
    b.attach_kprobe(event="zpl_iter_read", fn_name="trace_entry")
    b.attach_kprobe(event="zpl_iter_write", fn_name="trace_entry")
elif BPF.get_kprobe_functions(b'zpl_aio'):
    b.attach_kprobe(event="zpl_aio_read", fn_name="trace_entry")
    b.attach_kprobe(event="zpl_aio_write", fn_name="trace_entry")
else:
    b.attach_kprobe(event="zpl_read", fn_name="trace_entry")
    b.attach_kprobe(event="zpl_write", fn_name="trace_entry")
b.attach_kprobe(event="zpl_open", fn_name="trace_entry")
b.attach_kprobe(event="zpl_fsync", fn_name="trace_entry")
if BPF.get_kprobe_functions(b'zpl_iter'):
    b.attach_kretprobe(event="zpl_iter_read", fn_name="trace_read_return")
    b.attach_kretprobe(event="zpl_iter_write", fn_name="trace_write_return")
elif BPF.get_kprobe_functions(b'zpl_aio'):
    b.attach_kretprobe(event="zpl_aio_read", fn_name="trace_read_return")
    b.attach_kretprobe(event="zpl_aio_write", fn_name="trace_write_return")
else:
    b.attach_kretprobe(event="zpl_read", fn_name="trace_read_return")
    b.attach_kretprobe(event="zpl_write", fn_name="trace_write_return")
b.attach_kretprobe(event="zpl_open", fn_name="trace_open_return")
b.attach_kretprobe(event="zpl_fsync", fn_name="trace_fsync_return")

print("Tracing ZFS operation latency... Hit Ctrl-C to end.")

# output
exiting = 0
dist = b.get_table("dist")
while (1):
    try:
        if args.interval:
            sleep(int(args.interval))
        else:
            sleep(99999999)
    except KeyboardInterrupt:
        exiting = 1

    print()
    if args.interval and (not args.notimestamp):
        print(strftime("%H:%M:%S:"))

    dist.print_log2_hist(label, "operation")
    dist.clear()

    countdown -= 1
    if exiting or countdown == 0:
        exit()

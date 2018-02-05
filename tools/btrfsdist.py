#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# btrfsdist  Summarize btrfs operation latency.
#            For Linux, uses BCC, eBPF.
#
# USAGE: btrfsdist [-h] [-T] [-m] [-p PID] [interval] [count]
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 15-Feb-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse

# symbols
kallsyms = "/proc/kallsyms"

# arguments
examples = """examples:
    ./btrfsdist            # show operation latency as a histogram
    ./btrfsdist -p 181     # trace PID 181 only
    ./btrfsdist 1 10       # print 1 second summaries, 10 times
    ./btrfsdist -m 5       # 5s summaries, milliseconds
"""
parser = argparse.ArgumentParser(
    description="Summarize btrfs operation latency",
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

// The current btrfs (Linux 4.5) uses generic_file_read_iter() instead of it's
// own read function. So we need to trace that and then filter on btrfs, which
// I do by checking file->f_op.
int trace_read_entry(struct pt_regs *ctx, struct kiocb *iocb)
{
    u32 pid = bpf_get_current_pid_tgid();
    if (FILTER_PID)
        return 0;

    // btrfs filter on file->f_op == btrfs_file_operations
    struct file *fp = iocb->ki_filp;
    if ((u64)fp->f_op != BTRFS_FILE_OPERATIONS)
        return 0;

    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    return 0;
}

// The current btrfs (Linux 4.5) uses generic_file_open(), instead of it's own
// function. Same as with reads. Trace the generic path and filter:
int trace_open_entry(struct pt_regs *ctx, struct inode *inode,
    struct file *file)
{
    u32 pid;
    pid = bpf_get_current_pid_tgid();
    if (FILTER_PID)
        return 0;

    // btrfs filter on file->f_op == btrfs_file_operations
    if ((u64)file->f_op != BTRFS_FILE_OPERATIONS)
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

# code replacements
with open(kallsyms) as syms:
    ops = ''
    for line in syms:
        a = line.rstrip().split()
        (addr, name) = (a[0], a[2])
        name = name.split("\t")[0]
        if name == "btrfs_file_operations":
            ops = "0x" + addr
            break
    if ops == '':
        print("ERROR: no btrfs_file_operations in /proc/kallsyms. Exiting.")
        print("HINT: the kernel should be built with CONFIG_KALLSYMS_ALL.")
        exit()
    bpf_text = bpf_text.replace('BTRFS_FILE_OPERATIONS', ops)
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

# Common file functions. See earlier comment about generic_file_read_iter().
b.attach_kprobe(event="generic_file_read_iter", fn_name="trace_read_entry")
b.attach_kprobe(event="btrfs_file_write_iter", fn_name="trace_entry")
b.attach_kprobe(event="generic_file_open", fn_name="trace_open_entry")
b.attach_kprobe(event="btrfs_sync_file", fn_name="trace_entry")
b.attach_kretprobe(event="generic_file_read_iter", fn_name="trace_read_return")
b.attach_kretprobe(event="btrfs_file_write_iter", fn_name="trace_write_return")
b.attach_kretprobe(event="generic_file_open", fn_name="trace_open_return")
b.attach_kretprobe(event="btrfs_sync_file", fn_name="trace_fsync_return")

print("Tracing btrfs operation latency... Hit Ctrl-C to end.")

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

#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# filelife    Trace the lifespan of short-lived files.
#             For Linux, uses BCC, eBPF. Embedded C.
#
# This traces the creation and deletion of files, providing information
# on who deleted the file, the file age, and the file name. The intent is to
# provide information on short-lived files, for debugging or performance
# analysis.
#
# USAGE: filelife [-h] [-p PID]
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 08-Feb-2015   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime

# arguments
examples = """examples:
    ./filelife           # trace all stat() syscalls
    ./filelife -p 181    # only trace PID 181
"""
parser = argparse.ArgumentParser(
    description="Trace stat() syscalls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
    help="trace this PID only")
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>

BPF_HASH(birth, struct dentry *);

// trace file creation time
int trace_create(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
{
    u32 pid = bpf_get_current_pid_tgid();
    FILTER

    u64 ts = bpf_ktime_get_ns();
    birth.update(&dentry, &ts);

    return 0;
};

// trace file deletion and output details
int trace_unlink(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
{
    u32 pid = bpf_get_current_pid_tgid();
    FILTER

    u64 *tsp, delta;
    tsp = birth.lookup(&dentry);
    if (tsp == 0) {
        return 0;   // missed create
    }
    delta = (bpf_ktime_get_ns() - *tsp) / 1000000;
    birth.delete(&dentry);

    if (dentry->d_iname[0] == 0)
        return 0;

    bpf_trace_printk("%d %s\\n", delta, dentry->d_iname);

    return 0;
}
"""
if args.pid:
    bpf_text = bpf_text.replace('FILTER',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '')
if debug:
    print(bpf_text)

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="vfs_create", fn_name="trace_create")
b.attach_kprobe(event="vfs_unlink", fn_name="trace_unlink")

# header
print("%-8s %-6s %-16s %-7s %s" % ("TIME", "PID", "COMM", "AGE(s)", "FILE"))

start_ts = 0

# format output
while 1:
    (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    (delta, filename) = msg.split(" ", 1)

    # print columns
    print("%-8s %-6d %-16s %-7.2f %s" % (strftime("%H:%M:%S"), pid, task,
        float(delta) / 1000, filename))

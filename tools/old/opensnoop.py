#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# opensnoop Trace open() syscalls.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: opensnoop [-h] [-t] [-x] [-p PID]
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 17-Sep-2015   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
import argparse

# arguments
examples = """examples:
    ./opensnoop           # trace all open() syscalls
    ./opensnoop -t        # include timestamps
    ./opensnoop -x        # only show failed opens
    ./opensnoop -p 181    # only trace PID 181
"""
parser = argparse.ArgumentParser(
    description="Trace open() syscalls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-t", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-x", "--failed", action="store_true",
    help="only show failed opens")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

BPF_HASH(args_filename, u32, const char *);

int kprobe__sys_open(struct pt_regs *ctx, const char __user *filename)
{
    u32 pid = bpf_get_current_pid_tgid();

    FILTER
    args_filename.update(&pid, &filename);

    return 0;
};

int kretprobe__sys_open(struct pt_regs *ctx)
{
    const char **filenamep;
    int ret = ctx->ax;
    u32 pid = bpf_get_current_pid_tgid();

    filenamep = args_filename.lookup(&pid);
    if (filenamep == 0) {
        // missed entry
        return 0;
    }

    bpf_trace_printk("%d %s\\n", ret, *filenamep);
    args_filename.delete(&pid);

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

# header
if args.timestamp:
    print("%-14s" % ("TIME(s)"), end="")
print("%-6s %-16s %4s %3s %s" % ("PID", "COMM", "FD", "ERR", "PATH"))

start_ts = 0

# format output
while 1:
    (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    (ret_s, filename) = msg.split(" ", 1)

    ret = int(ret_s)
    if (args.failed and (ret >= 0)):
        continue

    # split return value into FD and errno columns
    if ret >= 0:
        fd_s = ret
        err = 0
    else:
        fd_s = "-1"
        err = - ret

    # print columns
    if args.timestamp:
        if start_ts == 0:
            start_ts = ts
        print("%-14.9f" % (ts - start_ts), end="")
    print("%-6d %-16s %4s %3s %s" % (pid, task, fd_s, err, filename))

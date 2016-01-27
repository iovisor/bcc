#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# killsnoop Trace signals issued by the kill() syscall.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: killsnoop [-h] [-t] [-x] [-p PID]
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 20-Sep-2015   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
import argparse

# arguments
examples = """examples:
    ./killsnoop           # trace all kill() signals
    ./killsnoop -t        # include timestamps
    ./killsnoop -x        # only show failed kills
    ./killsnoop -p 181    # only trace PID 181
"""
parser = argparse.ArgumentParser(
    description="Trace signals issued by the kill() syscall",
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

BPF_HASH(args_pid, u32, int);
BPF_HASH(args_sig, u32, int);

int kprobe__sys_kill(struct pt_regs *ctx, int tpid, int sig)
{
    u32 pid = bpf_get_current_pid_tgid();

    FILTER
    args_pid.update(&pid, &tpid);
    args_sig.update(&pid, &sig);

    return 0;
};

int kretprobe__sys_kill(struct pt_regs *ctx)
{
    int *tpidp, *sigp, ret = ctx->ax;
    u32 pid = bpf_get_current_pid_tgid();

    tpidp = args_pid.lookup(&pid);
    sigp = args_sig.lookup(&pid);
    if (tpidp == 0 || sigp == 0) {
        return 0;   // missed entry
    }

    bpf_trace_printk("%d %d %d\\n", *tpidp, *sigp, ret);
    args_pid.delete(&pid);
    args_sig.delete(&pid);

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
print("%-6s %-16s %-4s %-6s %s" % ("PID", "COMM", "SIG", "TPID", "RESULT"))

start_ts = 0

# format output
while 1:
    (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    (tpid_s, sig_s, ret_s) = msg.split(" ")

    ret = int(ret_s)
    if (args.failed and (ret >= 0)):
        continue

    # print columns
    if args.timestamp:
        if start_ts == 0:
            start_ts = ts
        print("%-14.9f" % (ts - start_ts), end="")
    print("%-6d %-16s %-4s %-6s %s" % (pid, task, sig_s, tpid_s, ret_s))

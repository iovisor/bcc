#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# execsnoop Trace new processes via exec() syscalls.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: execsnoop [-h] [-t] [-x] [-n NAME]
#
# This currently will print up to a maximum of 19 arguments, plus the process
# name, so 20 fields in total (MAXARG).
#
# This won't catch all new processes: an application may fork() but not exec().
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 07-Feb-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
import argparse
import re

# arguments
examples = """examples:
    ./execsnoop           # trace all exec() syscalls
    ./execsnoop -x        # include failed exec()s
    ./execsnoop -t        # include timestamps
    ./execsnoop -n main   # only print command lines containing "main"
"""
parser = argparse.ArgumentParser(
    description="Trace exec() syscalls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-t", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-x", "--fails", action="store_true",
    help="include failed exec()s")
parser.add_argument("-n", "--name",
    help="only print commands matching this name (regex), any arg")
args = parser.parse_args()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define MAXARG   20
#define ARGSIZE  64

static int print_arg(void *ptr) {
    // Fetch an argument, and print using bpf_trace_printk(). This is a work
    // around until we have a binary trace interface for passing event data to
    // bcc. Since exec()s should be low frequency, the additional overhead in
    // this case should not be a problem.
    const char *argp = NULL;
    char buf[ARGSIZE] = {};

    bpf_probe_read(&argp, sizeof(argp), ptr);
    if (argp == NULL) return 0;

    bpf_probe_read(&buf, sizeof(buf), (void *)(argp));
    bpf_trace_printk("ARG %s\\n", buf);

    return 1;
}

int kprobe__sys_execve(struct pt_regs *ctx, struct filename *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    char fname[ARGSIZE] = {};
    bpf_probe_read(&fname, sizeof(fname), (void *)(filename));
    bpf_trace_printk("ARG %s\\n", fname);

    int i = 1;  // skip first arg, as we printed fname

    // unrolled loop to walk argv[] (MAXARG)
    if (print_arg((void *)&__argv[i]) == 0) goto out; i++;
    if (print_arg((void *)&__argv[i]) == 0) goto out; i++;
    if (print_arg((void *)&__argv[i]) == 0) goto out; i++;
    if (print_arg((void *)&__argv[i]) == 0) goto out; i++;
    if (print_arg((void *)&__argv[i]) == 0) goto out; i++;
    if (print_arg((void *)&__argv[i]) == 0) goto out; i++;
    if (print_arg((void *)&__argv[i]) == 0) goto out; i++;
    if (print_arg((void *)&__argv[i]) == 0) goto out; i++;
    if (print_arg((void *)&__argv[i]) == 0) goto out; i++;
    if (print_arg((void *)&__argv[i]) == 0) goto out; i++; // X
    if (print_arg((void *)&__argv[i]) == 0) goto out; i++;
    if (print_arg((void *)&__argv[i]) == 0) goto out; i++;
    if (print_arg((void *)&__argv[i]) == 0) goto out; i++;
    if (print_arg((void *)&__argv[i]) == 0) goto out; i++;
    if (print_arg((void *)&__argv[i]) == 0) goto out; i++;
    if (print_arg((void *)&__argv[i]) == 0) goto out; i++;
    if (print_arg((void *)&__argv[i]) == 0) goto out; i++;
    if (print_arg((void *)&__argv[i]) == 0) goto out; i++;
    if (print_arg((void *)&__argv[i]) == 0) goto out; i++;
    if (print_arg((void *)&__argv[i]) == 0) goto out; i++; // XX
    bpf_trace_printk("ARG ...\\n");    // truncated

out:
    return 0;
}

int kretprobe__sys_execve(struct pt_regs *ctx)
{
    bpf_trace_printk("RET %d\\n", PT_REGS_RC(ctx));
    return 0;
}
"""

# initialize BPF
b = BPF(text=bpf_text)

# header
if args.timestamp:
    print("%-8s" % ("TIME(s)"), end="")
print("%-16s %-6s %3s %s" % ("PCOMM", "PID", "RET", "ARGS"))

start_ts = 0
cmd = {}
pcomm = {}

# format output
while 1:
    (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    try:
        (type, arg) = msg.split(" ", 1)
    except ValueError:
        continue

    if start_ts == 0:
        start_ts = ts

    if type == "RET":
        if pid not in cmd:
            # zero args
            cmd[pid] = ""
            pcomm[pid] = ""

        skip = 0
        if args.name:
            if not re.search(args.name, cmd[pid]):
                skip = 1
        if not args.fails and int(arg) < 0:
            skip = 1
        if skip:
            del cmd[pid]
            del pcomm[pid]
            continue

        # output
        if args.timestamp:
            print("%-8.3f" % (ts - start_ts), end="")
        print("%-16s %-6s %3s %s" % (pcomm[pid], pid, arg, cmd[pid]))
        del cmd[pid]
        del pcomm[pid]
    else:
        # build command line string
        if pid in cmd:
            cmd[pid] = cmd[pid] + " " + arg
        else:
            cmd[pid] = arg
        if pid not in pcomm:
            pcomm[pid] = task

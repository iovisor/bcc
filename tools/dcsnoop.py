#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# dcsnoop   Trace directory entry cache (dcache) lookups.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: dcsnoop [-h] [-a]
#
# By default, this traces every failed dcache lookup, and shows the process
# performing the lookup and the filename requested. A -a option can be used
# to show all lookups, not just failed ones.
#
# This uses kernel dynamic tracing of the d_lookup() function, and will need
# to be modified to match kernel changes.
#
# Also see dcstat(8), for per-second summaries.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 09-Feb-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
import argparse
import re

# arguments
examples = """examples:
    ./dcsnoop           # trace failed dcache lookups
    ./dcsnoop -a        # trace all dcache lookups
"""
parser = argparse.ArgumentParser(
    description="Trace directory entry cache (dcache) lookups",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-a", "--all", action="store_true",
    help="trace all lookups (default is fails only)")
args = parser.parse_args()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

#define MAX_FILE_LEN  64

struct entry_t {
    char name[MAX_FILE_LEN];
};

BPF_HASH(entrybypid, u32, struct entry_t);

/* from fs/namei.c: */
struct nameidata {
        struct path     path;
        struct qstr     last;
        // [...]
};

int trace_fast(struct pt_regs *ctx, struct nameidata *nd, struct path *path)
{
    bpf_trace_printk("R %s\\n", nd->last.name);
    return 1;
}

int kprobe__d_lookup(struct pt_regs *ctx, const struct dentry *parent,
    const struct qstr *name)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct entry_t entry = {};
    const char *fname = name->name;
    if (fname) {
        bpf_probe_read(&entry.name, sizeof(entry.name), (void *)fname);
    }
    entrybypid.update(&pid, &entry);
    return 0;
}

int kretprobe__d_lookup(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct entry_t *ep;
    ep = entrybypid.lookup(&pid);
    if (ep == 0) {
        return 0;   // missed entry
    }
    if (PT_REGS_RC(ctx) == 0) {
        bpf_trace_printk("M %s\\n", ep->name);
    }
    entrybypid.delete(&pid);
    return 0;
}
"""

# initialize BPF
b = BPF(text=bpf_text)
if args.all:
    b.attach_kprobe(event="lookup_fast", fn_name="trace_fast")

# header
print("%-11s %-6s %-16s %1s %s" % ("TIME(s)", "PID", "COMM", "T", "FILE"))

start_ts = 0

# format output
while 1:
    (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    try:
        (type, file) = msg.split(" ", 1)
    except ValueError:
        continue

    if start_ts == 0:
        start_ts = ts

    print("%-11.6f %-6s %-16s %1s %s" % (ts - start_ts, pid, task, type, file))

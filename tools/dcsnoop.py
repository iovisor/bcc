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
import ctypes as ct
import re
import time

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
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

#define MAX_FILE_LEN  64

enum lookup_type {
    LOOKUP_MISS,
    LOOKUP_REFERENCE,
};

struct entry_t {
    char name[MAX_FILE_LEN];
};

BPF_HASH(entrybypid, u32, struct entry_t);

struct data_t {
    u32 pid;
    enum lookup_type type;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILE_LEN];
};

BPF_PERF_OUTPUT(events);

/* from fs/namei.c: */
struct nameidata {
        struct path     path;
        struct qstr     last;
        // [...]
};

static inline
void submit_event(struct pt_regs *ctx, void *name, int type, u32 pid)
{
    struct data_t data = {
        .pid = pid,
        .type = type,
    };
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read(&data.filename, sizeof(data.filename), name);
    events.perf_submit(ctx, &data, sizeof(data));
}

int trace_fast(struct pt_regs *ctx, struct nameidata *nd, struct path *path)
{
    u32 pid = bpf_get_current_pid_tgid();
    submit_event(ctx, (void *)nd->last.name, LOOKUP_REFERENCE, pid);
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
    if (ep == 0 || PT_REGS_RC(ctx) != 0) {
        return 0;   // missed entry or lookup didn't fail
    }
    submit_event(ctx, (void *)ep->name, LOOKUP_MISS, pid);
    entrybypid.delete(&pid);
    return 0;
}
"""

TASK_COMM_LEN = 16  # linux/sched.h
MAX_FILE_LEN = 64  # see inline C

class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("type", ct.c_int),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("filename", ct.c_char * MAX_FILE_LEN),
    ]

if args.ebpf:
    print(bpf_text)
    exit()

# initialize BPF
b = BPF(text=bpf_text)
if args.all:
    b.attach_kprobe(event="lookup_fast", fn_name="trace_fast")

mode_s = {
    0: 'M',
    1: 'R',
}

start_ts = time.time()

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print("%-11.6f %-6d %-16s %1s %s" % (
            time.time() - start_ts, event.pid,
            event.comm.decode('utf-8', 'replace'), mode_s[event.type],
            event.filename.decode('utf-8', 'replace')))

# header
print("%-11s %-6s %-16s %1s %s" % ("TIME(s)", "PID", "COMM", "T", "FILE"))

b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    b.perf_buffer_poll()

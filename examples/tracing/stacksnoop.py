#!/usr/bin/python
#
# stacksnoop    Trace a kernel function and print all kernel stack traces.
#               For Linux, uses BCC, eBPF, and currently x86_64 only. Inline C.
#
# USAGE: stacksnoop [-h] [-p PID] [-s] [-v] function
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 12-Jan-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
import argparse
import ctypes as ct
import time

# arguments
examples = """examples:
    ./stacksnoop ext4_sync_fs    # print kernel stack traces for ext4_sync_fs
    ./stacksnoop -s ext4_sync_fs    # ... also show symbol offsets
    ./stacksnoop -v ext4_sync_fs    # ... show extra columns
    ./stacksnoop -p 185 ext4_sync_fs    # ... only when PID 185 is on-CPU
"""
parser = argparse.ArgumentParser(
    description="Trace and print kernel stack traces for a kernel function",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-s", "--offset", action="store_true",
    help="show address offsets")
parser.add_argument("-v", "--verbose", action="store_true",
    help="print more fields")
parser.add_argument("function",
    help="kernel function name")
args = parser.parse_args()
function = args.function
offset = args.offset
verbose = args.verbose
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u64 stack_id;
    u32 pid;
    char comm[TASK_COMM_LEN];
};

BPF_STACK_TRACE(stack_traces, 128);
BPF_PERF_OUTPUT(events);

void trace_stack(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    FILTER
    struct data_t data = {};
    data.stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID),
    data.pid = pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
}
"""
if args.pid:
    bpf_text = bpf_text.replace('FILTER',
        'if (pid != %s) { return; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '')
if debug:
    print(bpf_text)

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event=function, fn_name="trace_stack")

TASK_COMM_LEN = 16  # linux/sched.h

class Data(ct.Structure):
    _fields_ = [
        ("stack_id", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("comm", ct.c_char * TASK_COMM_LEN),
    ]

matched = b.num_open_kprobes()
if matched == 0:
    print("Function \"%s\" not found. Exiting." % function)
    exit()

stack_traces = b.get_table("stack_traces")
start_ts = time.time()

# header
if verbose:
    print("%-18s %-12s %-6s %-3s %s" %
            ("TIME(s)", "COMM", "PID", "CPU", "FUNCTION"))
else:
    print("%-18s %s" % ("TIME(s)", "FUNCTION"))

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents

    ts = time.time() - start_ts

    if verbose:
        print("%-18.9f %-12.12s %-6d %-3d %s" %
              (ts, event.comm.decode(), event.pid, cpu, function))
    else:
        print("%-18.9f %s" % (ts, function))

    for addr in stack_traces.walk(event.stack_id):
        sym = b.ksym(addr, show_offset=offset)
        print("\t%s" % sym)

    print()

b["events"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()

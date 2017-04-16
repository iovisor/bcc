#!/usr/bin/python
#
# stacksnoop    Trace a kernel function and print all kernel stack traces.
#               For Linux, uses BCC, eBPF, and currently x86_64 only. Inline C.
#
# USAGE: stacksnoop [-h] [-p PID] [-s] [-v] function
#
# The current implementation uses an unrolled loop for x86_64, and was written
# as a proof of concept. This implementation should be replaced in the future
# with an appropriate bpf_ call, when available.
#
# The stack depth is limited to 10 (+1 for the current instruction pointer).
# This could be tunable in a future version.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 12-Jan-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
import argparse

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

static int print_frame(u64 *bp, int *depth) {
    if (*bp) {
        // The following stack walker is x86_64 specific
        u64 ret = 0;
        if (bpf_probe_read(&ret, sizeof(ret), (void *)(*bp+8)))
            return 0;
        if (ret < __START_KERNEL_map)
            return 0;
        bpf_trace_printk("r%d: %llx\\n", *depth, ret);
        if (bpf_probe_read(bp, sizeof(*bp), (void *)*bp))
            return 0;
        *depth += 1;
        return 1;
    }
    return 0;
}

void trace_stack(struct pt_regs *ctx) {
    FILTER
    u64 bp = 0;
    int depth = 0;

    bpf_trace_printk("\\n");
    if (ctx->ip)
        bpf_trace_printk("ip: %llx\\n", ctx->ip);
    bp = ctx->bp;

    // unrolled loop, 10 frames deep:
    if (!print_frame(&bp, &depth)) return;
    if (!print_frame(&bp, &depth)) return;
    if (!print_frame(&bp, &depth)) return;
    if (!print_frame(&bp, &depth)) return;
    if (!print_frame(&bp, &depth)) return;
    if (!print_frame(&bp, &depth)) return;
    if (!print_frame(&bp, &depth)) return;
    if (!print_frame(&bp, &depth)) return;
    if (!print_frame(&bp, &depth)) return;
    if (!print_frame(&bp, &depth)) return;
};
"""
if args.pid:
    bpf_text = bpf_text.replace('FILTER',
        ('u32 pid; pid = bpf_get_current_pid_tgid(); ' +
        'if (pid != %s) { return; }') % (args.pid))
else:
    bpf_text = bpf_text.replace('FILTER', '')
if debug:
    print(bpf_text)

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event=function, fn_name="trace_stack")
matched = b.num_open_kprobes()
if matched == 0:
    print("Function \"%s\" not found. Exiting." % function)
    exit()

# header
if verbose:
    print("%-18s %-12s %-6s %-3s %s" % ("TIME(s)", "COMM", "PID", "CPU",
        "STACK"))
else:
    print("%-18s %s" % ("TIME(s)", "STACK"))

# format output
while 1:
    (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    if msg != "":
        (reg, addr) = msg.split(" ")
        ip = b.ksym(int(addr, 16), show_offset=offset)
        msg = msg + " " + ip
    if verbose:
        print("%-18.9f %-12.12s %-6d %-3d %s" % (ts, task, pid, cpu, msg))
    else:
        print("%-18.9f %s" % (ts, msg))

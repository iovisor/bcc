#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# softirqs  Summarize soft IRQ (interrupt) event time.
#           For Linux, uses BCC, eBPF.
#
# USAGE: softirqs [-h] [-T] [-N] [-d] [interval] [count]
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 20-Oct-2015   Brendan Gregg     Created this.
# 03-Apr-2017   Sasha Goldshtein  Migrated to kernel tracepoints.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse

# arguments
examples = """examples:
    ./softirqs            # sum soft irq event time
    ./softirqs -d         # show soft irq event time as histograms
    ./softirqs 1 10       # print 1 second summaries, 10 times
    ./softirqs -NT 1      # 1s summaries, nanoseconds, and timestamps
"""
parser = argparse.ArgumentParser(
    description="Summarize soft irq event time as histograms.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-N", "--nanoseconds", action="store_true",
    help="output in nanoseconds")
parser.add_argument("-d", "--dist", action="store_true",
    help="show distributions as histograms")
parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
countdown = int(args.count)
if args.nanoseconds:
    factor = 1
    label = "nsecs"
else:
    factor = 1000
    label = "usecs"
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

typedef struct irq_key {
    u32 vec;
    u64 slot;
} irq_key_t;

typedef struct account_val {
    u64 ts;
    u32 vec;
} account_val_t;

BPF_HASH(start, u32, account_val_t);
BPF_HASH(iptr, u32);
BPF_HISTOGRAM(dist, irq_key_t);

TRACEPOINT_PROBE(irq, softirq_entry)
{
    u32 pid = bpf_get_current_pid_tgid();
    account_val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.vec = args->vec;
    start.update(&pid, &val);
    return 0;
}

TRACEPOINT_PROBE(irq, softirq_exit)
{
    u64 delta;
    u32 vec;
    u32 pid = bpf_get_current_pid_tgid();
    account_val_t *valp;
    irq_key_t key = {0};

    // fetch timestamp and calculate delta
    valp = start.lookup(&pid);
    if (valp == 0) {
        return 0;   // missed start
    }
    delta = bpf_ktime_get_ns() - valp->ts;
    vec = valp->vec;

    // store as sum or histogram
    STORE

    start.delete(&pid);
    return 0;
}
"""

# code substitutions
if args.dist:
    bpf_text = bpf_text.replace('STORE',
        'key.vec = vec; key.slot = bpf_log2l(delta / %d); ' % factor +
        'dist.increment(key);')
else:
    bpf_text = bpf_text.replace('STORE',
        'key.vec = valp->vec; ' +
        'dist.increment(key, delta);')
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# load BPF program
b = BPF(text=bpf_text)

def vec_to_name(vec):
    # copied from softirq_to_name() in kernel/softirq.c
    # may need updates if new softirq handlers are added
    return ["hi", "timer", "net_tx", "net_rx", "block", "irq_poll",
            "tasklet", "sched", "hrtimer", "rcu"][vec]

print("Tracing soft irq event time... Hit Ctrl-C to end.")

# output
exiting = 0 if args.interval else 1
dist = b.get_table("dist")
while (1):
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = 1

    print()
    if args.timestamp:
        print("%-8s\n" % strftime("%H:%M:%S"), end="")

    if args.dist:
        dist.print_log2_hist(label, "softirq", section_print_fn=vec_to_name)
    else:
        print("%-16s %11s" % ("SOFTIRQ", "TOTAL_" + label))
        for k, v in sorted(dist.items(), key=lambda dist: dist[1].value):
            print("%-16s %11d" % (vec_to_name(k.vec), v.value / factor))
    dist.clear()

    countdown -= 1
    if exiting or countdown == 0:
        exit()

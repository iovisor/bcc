#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# hardirqs  Summarize hard IRQ (interrupt) event time.
#           For Linux, uses BCC, eBPF.
#
# USAGE: hardirqs [-h] [-T] [-N] [-C] [-d] [-c CPU] [interval] [outputs]
#
# Thanks Amer Ather for help understanding irq behavior.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 19-Oct-2015   Brendan Gregg   Created this.
# 22-May-2021   Hengqi Chen     Migrated to kernel tracepoints.
# 07-Mar-2022   Rocky Xing      Added CPU filter support.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import sys

# arguments
examples = """examples:
    ./hardirqs            # sum hard irq event time
    ./hardirqs -d         # show hard irq event time as histograms
    ./hardirqs 1 10       # print 1 second summaries, 10 times
    ./hardirqs -NT 1      # 1s summaries, nanoseconds, and timestamps
    ./hardirqs -c 1       # sum hard irq event time on CPU 1 only
"""
parser = argparse.ArgumentParser(
    description="Summarize hard irq event time as histograms",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-N", "--nanoseconds", action="store_true",
    help="output in nanoseconds")
parser.add_argument("-C", "--count", action="store_true",
    help="show event counts instead of timing")
parser.add_argument("-d", "--dist", action="store_true",
    help="show distributions as histograms")
parser.add_argument("-c", "--cpu", type=int,
    help="trace this CPU only")
parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("outputs", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
countdown = int(args.outputs)
if args.count and (args.dist or args.nanoseconds):
    print("The --count option can't be used with time-based options")
    exit()
if args.count:
    factor = 1
    label = "count"
elif args.nanoseconds:
    factor = 1
    label = "nsecs"
else:
    factor = 1000
    label = "usecs"
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/interrupt.h>

// Add cpu_id as part of key for irq entry event to handle the case which irq
// is triggered while idle thread(swapper/x, tid=0) for each cpu core.
// Please see more detail at pull request #2804, #3733.
typedef struct entry_key {
    u32 tid;
    u32 cpu_id;
} entry_key_t;

typedef struct irq_key {
    char name[32];
    u64 slot;
} irq_key_t;

typedef struct irq_name {
    char name[32];
} irq_name_t;

BPF_HASH(start, entry_key_t);
BPF_HASH(irqnames, entry_key_t, irq_name_t);
BPF_HISTOGRAM(dist, irq_key_t);
"""

bpf_text_count = """
TRACEPOINT_PROBE(irq, irq_handler_entry)
{
    struct entry_key key = {};
    irq_name_t name = {};
    u32 cpu = bpf_get_smp_processor_id();

    FILTER_CPU

    key.tid = bpf_get_current_pid_tgid();
    key.cpu_id = cpu;

    TP_DATA_LOC_READ_STR(&name.name, name, sizeof(name));
    irqnames.update(&key, &name);
    return 0;
}

TRACEPOINT_PROBE(irq, irq_handler_exit)
{
    struct entry_key key = {};
    u32 cpu = bpf_get_smp_processor_id();

    FILTER_CPU

    key.tid = bpf_get_current_pid_tgid();
    key.cpu_id = cpu;

    // check ret value of irq handler is not IRQ_NONE to make sure
    // the current event belong to this irq handler
    if (args->ret != IRQ_NONE) {
        irq_name_t *namep;

        namep = irqnames.lookup(&key);
        if (namep == 0) {
            return 0; // missed irq name
        }
        char *name = (char *)namep->name;
        irq_key_t key = {.slot = 0 /* ignore */};

        bpf_probe_read_kernel(&key.name, sizeof(key.name), name);
        dist.atomic_increment(key);
    }

    irqnames.delete(&key);
    return 0;
}
"""

bpf_text_time = """
TRACEPOINT_PROBE(irq, irq_handler_entry)
{
    u64 ts = bpf_ktime_get_ns();
    irq_name_t name = {};
    struct entry_key key = {};
    u32 cpu = bpf_get_smp_processor_id();

    FILTER_CPU

    key.tid = bpf_get_current_pid_tgid();
    key.cpu_id = cpu;

    TP_DATA_LOC_READ_STR(&name.name, name, sizeof(name));
    irqnames.update(&key, &name);
    start.update(&key, &ts);
    return 0;
}

TRACEPOINT_PROBE(irq, irq_handler_exit)
{
    u64 *tsp, delta;
    irq_name_t *namep;
    struct entry_key key = {};
    u32 cpu = bpf_get_smp_processor_id();

    key.tid = bpf_get_current_pid_tgid();
    key.cpu_id = cpu;

    // check ret value of irq handler is not IRQ_NONE to make sure
    // the current event belong to this irq handler
    if (args->ret != IRQ_NONE) {
        // fetch timestamp and calculate delta
        tsp = start.lookup(&key);
        namep = irqnames.lookup(&key);
        if (tsp == 0 || namep == 0) {
            return 0;   // missed start
        }

        char *name = (char *)namep->name;
        delta = bpf_ktime_get_ns() - *tsp;

        // store as sum or histogram
        STORE
    }

    start.delete(&key);
    irqnames.delete(&key);
    return 0;
}
"""

if args.count:
    bpf_text += bpf_text_count
else:
    bpf_text += bpf_text_time

# code substitutions
if args.dist:
    bpf_text = bpf_text.replace('STORE',
        'irq_key_t key = {.slot = bpf_log2l(delta / %d)};' % factor +
        'bpf_probe_read_kernel(&key.name, sizeof(key.name), name);' +
        'dist.atomic_increment(key);')
else:
    bpf_text = bpf_text.replace('STORE',
        'irq_key_t key = {.slot = 0 /* ignore */};' +
        'bpf_probe_read_kernel(&key.name, sizeof(key.name), name);' +
        'dist.atomic_increment(key, delta);')
if args.cpu is not None:
    bpf_text = bpf_text.replace('FILTER_CPU',
        'if (cpu != %d) { return 0; }' % int(args.cpu))
else:
    bpf_text = bpf_text.replace('FILTER_CPU', '')
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# load BPF program
b = BPF(text=bpf_text)

if args.count:
    print("Tracing hard irq events... Hit Ctrl-C to end.")
else:
    print("Tracing hard irq event time... Hit Ctrl-C to end.")

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
        dist.print_log2_hist(label, "hardirq", section_print_fn=bytes.decode)
    else:
        print("%-26s %11s" % ("HARDIRQ", "TOTAL_" + label))
        for k, v in sorted(dist.items(), key=lambda dist: -dist[1].value):
            print("%-26s %11d" % (k.name.decode('utf-8', 'replace'), v.value / factor))
    dist.clear()

    sys.stdout.flush()

    countdown -= 1
    if exiting or countdown == 0:
        exit()

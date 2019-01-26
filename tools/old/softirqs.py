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
# 20-Oct-2015   Brendan Gregg   Created this.

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
    description="Summarize soft irq event time as histograms",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-N", "--nanoseconds", action="store_true",
    help="output in nanoseconds")
parser.add_argument("-d", "--dist", action="store_true",
    help="show distributions as histograms")
parser.add_argument("-C", "--bycpu", action="store_true",
    help="break down softirqs to individual cpus")
parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
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
bpf_text = ""
if args.bycpu:
    bpf_text = """
    #include <uapi/linux/ptrace.h>

    typedef struct irq_cpu_key {
        s64 cpu;
        u64 slot;
    } irq_key_t;

    BPF_HASH(start, u32);
    BPF_HISTOGRAM(dist, irq_key_t);

    // time IRQ
    int trace_start_cpu(struct pt_regs *ctx)
    {
        int curr_cpu = bpf_get_smp_processor_id();
        u64 ts = bpf_ktime_get_ns();
        start.update(&curr_cpu, &ts);
        return 0;
    }

    int trace_completion_cpu(struct pt_regs *ctx)
    {
        u64 *tsp, delta;
        int curr_cpu = bpf_get_smp_processor_id();

        // fetch timestamp and calculate delta
        tsp = start.lookup(&curr_cpu);
        COMMON

        // store as sum or histogram
        irq_key_t key = {.cpu = curr_cpu,
        STORE

        start.delete(&curr_cpu);
        return 0;
    }
    """
else:
    bpf_text = """
    #include <uapi/linux/ptrace.h>

    typedef struct irq_key {
        u64 ip;
        u64 slot;
    } irq_key_t;

    BPF_HASH(start, u32);
    BPF_HASH(iptr, u32);
    BPF_HISTOGRAM(dist, irq_key_t);

    // time IRQ
    int trace_start(struct pt_regs *ctx)
    {
        u32 pid = bpf_get_current_pid_tgid();
        u64 ip = PT_REGS_IP(ctx), ts = bpf_ktime_get_ns();
        start.update(&pid, &ts);
        iptr.update(&pid, &ip);
        return 0;
    }

    int trace_completion(struct pt_regs *ctx)
    {
        u64 *tsp, delta, ip, *ipp;
        u32 pid = bpf_get_current_pid_tgid();
        // fetch timestamp and calculate delta
        tsp = start.lookup(&pid);
        ipp = iptr.lookup(&pid);
        COMMON

        // store as sum or histogram
        irq_key_t key = {
        STORE

        start.delete(&pid);
        iptr.delete(&pid);
        return 0;
    }
    """

# code substitutions
bpf_text = bpf_text.replace('COMMON',
        """if (tsp == 0) {
            return 0;   // missed start
        }
        delta = bpf_ktime_get_ns() - *tsp;
        """)

if args.dist:
    bpf_text = bpf_text.replace('STORE',
        '.slot = bpf_log2l(delta)};' +
        'dist.increment(key);')
else:
    bpf_text = bpf_text.replace('STORE',
        ' .ip = ip, .slot = 0 /* ignore */};' +
        'u64 zero = 0, *vp = dist.lookup_or_init(&key, &zero);' +
        '(*vp) += delta;')
if debug:
    print(bpf_text)

# load BPF program
b = BPF(text=bpf_text)

# this should really use irq:softirq_entry/exit tracepoints; for now the
# soft irq functions are individually traced (search your kernel for
# open_softirq() calls, and adjust the following list as needed).
for softirqfunc in ("blk_iopoll_softirq", "blk_done_softirq",
        "rcu_process_callbacks", "run_rebalance_domains", "tasklet_action",
        "tasklet_hi_action", "run_timer_softirq", "net_tx_action",
        "net_rx_action"):
    if args.bycpu:
        b.attach_kprobe(event=softirqfunc, fn_name="trace_start_cpu")
        b.attach_kretprobe(event=softirqfunc, fn_name="trace_completion_cpu")
    else:
        b.attach_kprobe(event=softirqfunc, fn_name="trace_start")
        b.attach_kretprobe(event=softirqfunc, fn_name="trace_completion")

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
        if args.bycpu:
            dist.print_log2_hist(label, "CPU")
        else:
            dist.print_log2_hist(label, "softirq", section_print_fn=b.ksym)
    else:
        if args.bycpu:
            print("%-26s %11s %11s" % ("SOFTIRQ", "CPU", "TOTAL_" + label))
            for k, v in sorted(dist.items(), key=lambda dist: dist[1].value):
                print("%-26s %11d %11d" % (b.ksym(k.ip), k.cpu, v.value / factor))
        else:
            print("%-26s %11s" % ("SOFTIRQ", "TOTAL_" + label))
            for k, v in sorted(dist.items(), key=lambda dist: dist[1].value):
                print("%-26s %11d" % (b.ksym(k.ip), v.value / factor))
    dist.clear()

    countdown -= 1
    if exiting or countdown == 0:
        exit()

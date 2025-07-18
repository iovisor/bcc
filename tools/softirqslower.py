#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# softirqlat  Trace slow soft IRQ (interrupt).
#             For Linux, uses BCC, eBPF.
#
# USAGE: softirqslower [-h] [-c CPU] [min_us]
#
# Copyright (c) 2025 Chenyue Zhou.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 08-Jul-2025   Chenyue Zhou     Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import sys

# arguments
examples = """examples:
    ./softirqslower        # trace softirq latency higher than 10000 us (default)
    ./softirqslower 100000 # trace softirq latency higher than 100000 us
    ./softirqslower -c 1   # trace softirq latency on CPU 1 only
"""

parser = argparse.ArgumentParser(
        description="Trace slow soft IRQ (interrupt).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
parser.add_argument("min_us", nargs="?", default="10000",
        help="minimum softirq latency to trace, in us (default 10000)")
parser.add_argument("-c", "--cpu", type=int, help="trace this CPU only")
parser.add_argument("--ebpf", action="store_true", help=argparse.SUPPRESS)
args = parser.parse_args()

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/interrupt.h>

enum {
    SOFTIRQ_RAISE,
    SOFTIRQ_ENTRY,
    SOFTIRQ_EXIT,
    SOFTIRQ_MAX_STAGE,
};

struct counter {
    u64 ts;
    u8 not_first;
};

struct data {
    u32 reserved;
    u32 stage;
    u32 vec;
    u32 cpu;
    u64 delta_ns;
    char task[TASK_COMM_LEN];
};

BPF_PERCPU_ARRAY(raise, struct counter, NR_SOFTIRQS);
BPF_PERCPU_ARRAY(entry, struct counter, NR_SOFTIRQS);
BPF_PERF_OUTPUT(softirq_events);

static __always_inline void event_collect(void *ctx, u32 stage, u32 vec,
    u32 cpu, u64 delta_ns)
{
    struct data dt = {
        .stage = stage,
        .vec = vec,
        .cpu = cpu,
        .delta_ns = delta_ns,
    };
    bpf_get_current_comm(&dt.task, sizeof(dt.task));
    softirq_events.perf_submit(ctx, &dt, sizeof(dt));
}

RAW_TRACEPOINT_PROBE(softirq_raise)
{
    u32 cpu = bpf_get_smp_processor_id();
    u32 vec = (u32)(ctx->args[0]);

    FILTER_CPU

    struct counter *data = raise.lookup(&vec);
    if (!data)
        return 0;

    if (data->ts) {
        // TODO record event
        return 0;
    }

    data->not_first = 1;
    data->ts = bpf_ktime_get_ns();

    return 0;
}

RAW_TRACEPOINT_PROBE(softirq_entry)
{
    u32 cpu = bpf_get_smp_processor_id();
    u32 vec = (u32)(ctx->args[0]);

    FILTER_CPU

    struct counter *data = raise.lookup(&vec);
    if (!data)
        return 0;

    if ((data->not_first) && !(data->ts)) {
        // TODO record miss event
        return 0;
    }

    u64 cur_ts = bpf_ktime_get_ns();
    u64 delta_ns = cur_ts - data->ts;
    data->ts = 0;

    if (DELTA_FILTER) {
        event_collect(ctx, SOFTIRQ_ENTRY, vec, cpu, delta_ns);
    }
    data = entry.lookup(&vec);
    if (!data)
        return 0;

    data->not_first = 1;
    data->ts = cur_ts;

    return 0;
}

RAW_TRACEPOINT_PROBE(softirq_exit)
{
    u32 cpu = bpf_get_smp_processor_id();
    u32 vec = (u32)(ctx->args[0]);

    FILTER_CPU

    struct counter *data = entry.lookup(&vec);
    if (!data)
        return 0;

    if ((data->not_first) && !(data->ts)) {
        // TODO record miss event
        return 0;
    }

    u64 cur_ts = bpf_ktime_get_ns();
    u64 delta_ns = cur_ts - data->ts;
    data->ts = 0;

    if (DELTA_FILTER) {
        event_collect(ctx, SOFTIRQ_EXIT, vec, cpu, delta_ns);
    }

    return 0;
}
"""

def vec_to_name(vec):
    return ["hi", "timer", "net_tx", "net_rx", "block", "irq_poll", "tasklet",
            "sched", "hrtimer", "rcu"][vec]

def stage_to_name(stage):
    return ["raise softirq", "irq(hard) to softirq", "softirq runtime"][stage]

def print_event(cpu, data, size):
    event = b["softirq_events"].event(data)
    print("%-8s %-20s %-8s %-14d %-6d %-6s" % (strftime("%H:%M:%S"),
            stage_to_name(event.stage), vec_to_name(event.vec),
            event.delta_ns / 1000, event.cpu, event.task.decode("utf-8",
                "replace")))

if __name__ == "__main__":
    if args.cpu is not None:
        bpf_text = bpf_text.replace("FILTER_CPU",
                'if (cpu != %d) { return 0; }' % int(args.cpu))
    else:
        bpf_text = bpf_text.replace("FILTER_CPU", "")

    bpf_text = bpf_text.replace("DELTA_FILTER", "delta_ns >= %d" % \
            (int(args.min_us) * 1000))

    if args.ebpf:
        print(bpf_text)
        exit()

    b = BPF(text=bpf_text)
    b["softirq_events"].open_perf_buffer(print_event, page_cnt=64)

    print("Tracing softirq latency higher than %d us... Hit Ctrl-C to end." % \
            int(args.min_us))

    print("%-8s %-20s %-8s %-14s %-6s %-6s" % ("TIME", "STAGE", "SOFTIRQ",
        "LAT(us)", "CPU", "COMM"))
    while (1):
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

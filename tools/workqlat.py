#!/usr/libexec/platform-python
# @lint-avoid-python-3-compatibility-imports
#
# workqlat   Work queue latency as a histogram.
#           For Linux, uses BCC, eBPF.
#
# USAGE: workqlat [-w] [interval] [count]
#
# This measures the time a work item spends waiting on a work queue before
# being executed by a worker, and shows this time as a histogram. This time
# should be small, but execution of work item may get delayed due to CPU load.
#
#
# Copyright 2022 Oracle and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# Inspired by runqlat
# 06-Jan-2022   Imran Khan   Created this.

from __future__ import (
    absolute_import, division, unicode_literals, print_function
)
from bcc import BPF
from time import sleep
import argparse

# arguments
examples = """examples:
    ./workqlat           # summarize work queue latency as a histogram
    ./workqlat 1 10      # print 1 second summaries, 10 times
    ./workqlat -W        # show each work-handler item separately
    ./workqlat -w xyz    # show specified work handler
"""
parser = argparse.ArgumentParser(
    description="Summarize work queue latency as a histogram",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-W", "--works", action="store_true",
    help="print a histogram per work-handler item")
parser.add_argument("-w", "--work",
    help="trace only specified work item")
parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
arguments = parser.parse_args()
countdown = int(arguments.count)
debug = 0

src = """
#include <uapi/linux/ptrace.h>

typedef struct work_key {
    u64 work;
    u64 handle;
} work_key_t;

typedef struct work_handle_key {
    u64 handle;
    u64 slot;
} work_handle_key_t;

BPF_HASH(record, work_key_t);

STORAGE

TRACEPOINT_PROBE(workqueue, workqueue_queue_work) {
    work_key_t key = {};

    FILTER

    u64 ts = bpf_ktime_get_ns();
    key.work = (u64)args->work;
    key.handle = (u64)args->function;
    record.update(&key, &ts);

    return 0;
}

TRACEPOINT_PROBE(workqueue, workqueue_execute_start) {
    work_key_t key = {};
    u64 *ts = NULL;
    u64 delta = 0;
    u64 handle = 0;

    FILTER

    key.work = (u64)args->work;
    key.handle = (u64)args->function;
    ts = record.lookup(&key);
    if (ts != NULL) {
        delta = bpf_ktime_get_ns() - *ts;
        delta = delta / 1000; //nanosec to microsec
        handle = (u64)args->function;
        STORE
        record.delete(&key);
    }

    return 0;
}
"""

# code substitutions
label = "usecs"

if arguments.works:
    section = "work handles"
    handle = "handle"
    src = src.replace('STORAGE', 'BPF_HISTOGRAM(dist, work_handle_key_t);')
    src = src.replace('STORE',
            'work_handle_key_t hkey = {.handle = ' + handle
            + ', .slot = bpf_log2l(delta)}; '
            + 'dist.increment(hkey);')
else:
    section = ""
    src = src.replace('STORAGE', 'BPF_HISTOGRAM(dist);')
    src = src.replace('STORE', 'dist.increment(bpf_log2l(delta));')

if arguments.work:
    func_name = BPF.ksymname((arguments.work))
    if (func_name < 0):
        print("Invalid work handler \n")
        exit()

    src = src.replace('FILTER',
        """u64 val = 0x%x;
        int ret;
        if ((u64)args->function != val)
        return 0;""" % func_name)

else:
    src = src.replace('FILTER', '')

if debug or arguments.ebpf:
    print(bpf_text)
    if arguments.ebpf:
        exit()

# load BPF program
b = BPF(text=src)

if arguments.work:
    print("Tracing work queue latency for "
          + arguments.work + "... Hit Ctrl-C to end.")
else:
    print("Tracing work queue latency ... Hit Ctrl-C to end.")

# output
exiting = 0 if arguments.interval else 1
dist = b.get_table("dist")
while (1):
    try:
        sleep(int(arguments.interval))
    except KeyboardInterrupt:
        exiting = 1

    print()
    print("Printing histogram")
    dist.print_log2_hist(label, section, section_print_fn=b.ksym)
    dist.clear()

    countdown -= 1
    if exiting or countdown == 0:
        exit()

#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# wqlat Summarize kernel workqueue latency as a histogram.
#           For Linux, uses BCC, eBPF.
#
# USAGE: wqlat [-h] [-T] [-N] [-W] [-w WQNAME] [interval] [count]
#
# Copyright (c) ping gan.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 29-Jan-2024   ping gan     Created this.


from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import sys

# arguments
examples = """examples:
    ./wqlat                   # summarize workqueue latency as a histogram
    ./wqlat 1 10              # print 1 second summaries, 10 times
    ./wqlat -W 1 10           # print 1 second, 10 times per workqueue
    ./wqlat -NT 1             # 1s summaries, nanoseconds, and timestamps
    ./wqlat -w nvmet_tcp_wq 1 # 1s summaries for workqueue nvmet_tcp_wq
"""
parser = argparse.ArgumentParser(
    description="Summarize workqueue request latency as histograms.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-N", "--nanoseconds", action="store_true",
    help="output in nanoseconds")
parser.add_argument("-W", "--workqueues", action="store_true",
    help="print a histogram per work queue")
parser.add_argument("-w", "--wqname", type=str,
    help="print this workqueue only")
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
if args.wqname and len(args.wqname) >= 24:
    print("workqueue name len must be less than 24")
    exit(-1)

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/workqueue.h>

#define WQ_NAME_LEN   (24)
typedef struct wq_val {
    char wq_name[WQ_NAME_LEN];
    u64 ts;
} wq_val_t;
KEY_DEFINE
BPF_HASH(start, u64, wq_val_t);
STORAGE

static int cmp_wqname(const char *name1, const char *name2, int size)
{
    int len = 0;
    unsigned char c1, c2;
    while (len++ < size) {
        c1 = *name1++;
        c2 = *name2++;
        if (c1 != c2)
            return c1 < c2 ? -1 : 1;
        if (!c1)
            break;
    }
    return 0;
}

TRACEPOINT_PROBE(workqueue, workqueue_queue_work)
{
    wq_val_t wqval = {};
    TP_DATA_LOC_READ_STR(&wqval.wq_name, workqueue, sizeof(wqval.wq_name));
    FILTER_WQ
    u64 work_addr = (u64)args->work;
    wqval.ts = bpf_ktime_get_ns();
    start.update(&work_addr, &wqval);
    return 0;
}

TRACEPOINT_PROBE(workqueue, workqueue_execute_start)
{
    u64 work_addr = (u64)args->work;
    wq_val_t *valp = start.lookup(&work_addr);
    if (valp == 0 ) {
        return 0;   // missed start
    }
    u64 ts = bpf_ktime_get_ns();
    u64 delta = ts - valp->ts;
    FACTOR
    STORE
    start.delete(&work_addr);
    return 0;
}
"""

# code substitutions
bpf_text = bpf_text.replace('FACTOR', 'delta /= %d;' % factor)
if args.workqueues:
    bpf_key_text = """
    typedef struct wq_key {
        char wq_name[WQ_NAME_LEN];
        u64 slot;
    } wq_key_t;
    """
    bpf_storage_text = """
    BPF_HISTOGRAM(dist, wq_key_t);
    """
    bpf_store_text = """
    wq_key_t wqk = {};
    wqk.slot = bpf_log2l(delta);
    bpf_probe_read_kernel(&wqk.wq_name, sizeof(wqk.wq_name), valp->wq_name);
    dist.atomic_increment(wqk);
    """
    bpf_text = bpf_text.replace('KEY_DEFINE', bpf_key_text)
    bpf_text = bpf_text.replace('STORAGE', bpf_storage_text)
    bpf_text = bpf_text.replace('STORE', bpf_store_text)
else:
    bpf_text = bpf_text.replace('KEY_DEFINE', '')
    bpf_text = bpf_text.replace('STORAGE', 'BPF_HISTOGRAM(dist);')
    bpf_text = bpf_text.replace('STORE',
                        'dist.atomic_increment(bpf_log2l(delta));')

if args.wqname:
    bpf_wq_filter_text = """
    if(cmp_wqname(wqval.wq_name, "%s", WQ_NAME_LEN)) {
        return 0;
    }
    """ % (args.wqname)
    bpf_text = bpf_text.replace('FILTER_WQ', bpf_wq_filter_text)
else:
    bpf_text = bpf_text.replace('FILTER_WQ', '')
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()
def wqname_print(wq_name):
    wqname = wq_name.decode('utf-8')
    return wqname

# load BPF program
b = BPF(text=bpf_text)
print("Tracing work queue request latency time... Hit Ctrl-C to end.")

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
    dist.print_log2_hist(label, "wqname", wqname_print)
    dist.clear()

    countdown -= 1
    if exiting or countdown == 0:
        exit()

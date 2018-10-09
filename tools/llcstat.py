#!/usr/bin/python
#
# llcstat.py Summarize cache references and cache misses by PID.
#            Cache reference and cache miss are corresponding events defined in
#            uapi/linux/perf_event.h, it varies to different architecture.
#            On x86-64, they mean LLC references and LLC misses.
#
#            For Linux, uses BCC, eBPF. Embedded C.
#
# SEE ALSO: perf top -e cache-misses -e cache-references -a -ns pid,cpu,comm
#
# REQUIRES: Linux 4.9+ (BPF_PROG_TYPE_PERF_EVENT support).
#
# Copyright (c) 2016 Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 19-Oct-2016   Teng Qin   Created this.

from __future__ import print_function
import argparse
from bcc import BPF, PerfType, PerfHWConfig
import signal
from time import sleep

parser = argparse.ArgumentParser(
    description="Summarize cache references and misses by PID",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument(
    "-c", "--sample_period", type=int, default=100,
    help="Sample one in this many number of cache reference / miss events")
parser.add_argument(
    "duration", nargs="?", default=10, help="Duration, in seconds, to run")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

# load BPF program
bpf_text="""
#include <linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>

struct key_t {
    int cpu;
    int pid;
    char name[TASK_COMM_LEN];
};

BPF_HASH(ref_count, struct key_t);
BPF_HASH(miss_count, struct key_t);

static inline __attribute__((always_inline)) void get_key(struct key_t* key) {
    key->cpu = bpf_get_smp_processor_id();
    key->pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&(key->name), sizeof(key->name));
}

int on_cache_miss(struct bpf_perf_event_data *ctx) {
    struct key_t key = {};
    get_key(&key);

    miss_count.increment(key, ctx->sample_period);

    return 0;
}

int on_cache_ref(struct bpf_perf_event_data *ctx) {
    struct key_t key = {};
    get_key(&key);

    ref_count.increment(key, ctx->sample_period);

    return 0;
}
"""

if args.ebpf:
    print(bpf_text)
    exit()

b = BPF(text=bpf_text)
try:
    b.attach_perf_event(
        ev_type=PerfType.HARDWARE, ev_config=PerfHWConfig.CACHE_MISSES,
        fn_name="on_cache_miss", sample_period=args.sample_period)
    b.attach_perf_event(
        ev_type=PerfType.HARDWARE, ev_config=PerfHWConfig.CACHE_REFERENCES,
        fn_name="on_cache_ref", sample_period=args.sample_period)
except:
    print("Failed to attach to a hardware event. Is this a virtual machine?")
    exit()

print("Running for {} seconds or hit Ctrl-C to end.".format(args.duration))

try:
    sleep(float(args.duration))
except KeyboardInterrupt:
    signal.signal(signal.SIGINT, lambda signal, frame: print())

miss_count = {}
for (k, v) in b.get_table('miss_count').items():
    miss_count[(k.pid, k.cpu, k.name)] = v.value

print('PID      NAME             CPU     REFERENCE         MISS    HIT%')
tot_ref = 0
tot_miss = 0
for (k, v) in b.get_table('ref_count').items():
    try:
        miss = miss_count[(k.pid, k.cpu, k.name)]
    except KeyError:
        miss = 0
    tot_ref += v.value
    tot_miss += miss
    # This happens on some PIDs due to missed counts caused by sampling
    hit = (v.value - miss) if (v.value >= miss) else 0
    print('{:<8d} {:<16s} {:<4d} {:>12d} {:>12d} {:>6.2f}%'.format(
        k.pid, k.name.decode('utf-8', 'replace'), k.cpu, v.value, miss,
        (float(hit) / float(v.value)) * 100.0))
print('Total References: {} Total Misses: {} Hit Rate: {:.2f}%'.format(
    tot_ref, tot_miss, (float(tot_ref - tot_miss) / float(tot_ref)) * 100.0))

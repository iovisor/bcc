#!/usr/bin/python
#
# cachestat     Count cache kernel function calls.
#               For Linux, uses BCC, eBPF. See .c file.
#
# USAGE: cachestat
# Taken from funccount by Brendan Gregg
# This is a rewrite of cachestat from perf to bcc
# https://github.com/brendangregg/perf-tools/blob/master/fs/cachestat
#
# Copyright (c) 2016 Allan McAleavy.
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 09-Sep-2015   Brendan Gregg   Created this.
# 06-Nov-2015   Allan McAleavy
# 13-Jan-2016   Allan McAleavy  run pep8 against program

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import signal
import re
from sys import argv

# signal handler
def signal_ignore(signal, frame):
    print()

# Function to gather data from /proc/meminfo
# return dictionary for quicker lookup of both values
def get_meminfo():
    result = dict()

    for line in open('/proc/meminfo'):
        k = line.split(':', 3)
        v = k[1].split()
        result[k[0]] = int(v[0])
    return result

# set global variables
mpa = 0
mbd = 0
apcl = 0
apd = 0
total = 0
misses = 0
hits = 0
debug = 0

# args
def usage():
    print("USAGE: %s [-T] [ interval [count] ]" % argv[0])
    exit()

# arguments
interval = 5
count = -1
tstamp = 0

if len(argv) > 1:
    if str(argv[1]) == '-T':
        tstamp = 1

if len(argv) > 1 and tstamp == 0:
    try:
        if int(argv[1]) > 0:
            interval = int(argv[1])
        if len(argv) > 2:
            if int(argv[2]) > 0:
                count = int(argv[2])
    except:
        usage()

elif len(argv) > 2 and tstamp == 1:
    try:
        if int(argv[2]) > 0:
            interval = int(argv[2])
        if len(argv) >= 4:
            if int(argv[3]) > 0:
                count = int(argv[3])
    except:
        usage()

# load BPF program
bpf_text = """

#include <uapi/linux/ptrace.h>
struct key_t {
    u64 ip;
};

BPF_HASH(counts, struct key_t);

int do_count(struct pt_regs *ctx) {
    struct key_t key = {};
    u64 zero = 0, *val;
    u64 ip;

    key.ip = PT_REGS_IP(ctx);
    val = counts.lookup_or_init(&key, &zero);  // update counter
    (*val)++;
    return 0;
}

"""
b = BPF(text=bpf_text)
b.attach_kprobe(event="add_to_page_cache_lru", fn_name="do_count")
b.attach_kprobe(event="mark_page_accessed", fn_name="do_count")
b.attach_kprobe(event="account_page_dirtied", fn_name="do_count")
b.attach_kprobe(event="mark_buffer_dirty", fn_name="do_count")

# header
if tstamp:
    print("%-8s " % "TIME", end="")
print("%8s %8s %8s %8s %12s %10s" %
     ("TOTAL", "MISSES", "HITS", "DIRTIES", "BUFFERS_MB", "CACHED_MB"))

loop = 0
exiting = 0
while 1:
    if count > 0:
        loop += 1
        if loop > count:
            exit()

    try:
        sleep(interval)
    except KeyboardInterrupt:
        exiting = 1
        # as cleanup can take many seconds, trap Ctrl-C:
        signal.signal(signal.SIGINT, signal_ignore)

    counts = b.get_table("counts")
    for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):

        if re.match(b'mark_page_accessed', b.ksym(k.ip)) is not None:
            mpa = max(0, v.value)

        if re.match(b'mark_buffer_dirty', b.ksym(k.ip)) is not None:
            mbd = max(0, v.value)

        if re.match(b'add_to_page_cache_lru', b.ksym(k.ip)) is not None:
            apcl = max(0, v.value)

        if re.match(b'account_page_dirtied', b.ksym(k.ip)) is not None:
            apd = max(0, v.value)

        # total = total cache accesses without counting dirties
        # misses = total of add to lru because of read misses
        total = (mpa - mbd)
        misses = (apcl - apd)

        if total < 0:
            total = 0

        if misses < 0:
            misses = 0

        hits = total - misses

        # If hits are < 0, then its possible misses are overestimated
        # due to possibly page cache read ahead adding more pages than
        # needed. In this case just assume misses as total and reset hits.
        if hits < 0:
            misses = total
            hits = 0

    if debug:
        print("%d %d %d %d %d %d %d\n" %
        (mpa, mbd, apcl, apd, total, misses, hits))

    counts.clear()

    # Get memory info
    mem = get_meminfo()
    cached = int(mem["Cached"]) / 1024
    buff = int(mem["Buffers"]) / 1024

    if tstamp == 1:
        print("%-8s " % strftime("%H:%M:%S"), end="")
    print("%8d %8d %8d %8d %12.0f %10.0f" %
    (total, misses, hits, mbd, buff, cached))

    mpa = 0
    mbd = 0
    apcl = 0
    apd = 0
    total = 0
    misses = 0
    hits = 0
    cached = 0
    buff = 0

    if exiting:
        print("Detaching...")
        exit()

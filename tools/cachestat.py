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
from time import sleep, strftime
from libs import cache, utils
from sys import argv


# set global variables
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
b = cache.bpf_start(bpf_text)

# header
if tstamp:
    print("%-8s " % "TIME", end="")
print("%8s %8s %8s %10s %10s %12s %10s" %
     ("HITS", "MISSES", "DIRTIES",
     "READ_HIT%", "WRITE_HIT%", "BUFFERS_MB", "CACHED_MB"))

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
        utils.handle_sigint()

    counts = b.get_table("counts")
    (access, misses, mbd, rhits, whits) = cache.compute_cache_stats(
        counts, debug=debug)
    counts.clear()

    # Get memory info
    mem = utils.get_meminfo()
    cached = int(mem["Cached"]) / 1024
    buff = int(mem["Buffers"]) / 1024

    if tstamp == 1:
        print("%-8s " % strftime("%H:%M:%S"), end="")
    print("%8d %8d %8d %9.1f%% %9.1f%% %12.0f %10.0f" % (
            access, misses, mbd, rhits, whits, buff, cached))

    if exiting:
        print("Detaching...")
        exit()

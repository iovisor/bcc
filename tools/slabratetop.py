#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# slabratetop  Summarize kmem_cache_alloc() calls.
#              For Linux, uses BCC, eBPF.
#
# USAGE: slabratetop [-h] [-C] [-r MAXROWS] [interval] [count]
#
# This uses in-kernel BPF maps to store cache summaries for efficiency.
#
# SEE ALSO: slabtop(1), which shows the cache volumes.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 15-Oct-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from time import sleep, strftime
import argparse
import signal
from subprocess import call

# arguments
examples = """examples:
    ./slabratetop            # kmem_cache_alloc() top, 1 second refresh
    ./slabratetop -C         # don't clear the screen
    ./slabratetop 5          # 5 second summaries
    ./slabratetop 5 10       # 5 second summaries, 10 times only
"""
parser = argparse.ArgumentParser(
    description="Kernel SLAB/SLUB memory cache allocation rate top",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-C", "--noclear", action="store_true",
    help="don't clear the screen")
parser.add_argument("-r", "--maxrows", default=20,
    help="maximum rows to print, default 20")
parser.add_argument("interval", nargs="?", default=1,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
interval = int(args.interval)
countdown = int(args.count)
maxrows = int(args.maxrows)
clear = not int(args.noclear)
debug = 0

# linux stats
loadavg = "/proc/loadavg"

# signal handler
def signal_ignore(signal, frame):
    print()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/mm.h>
#include <linux/slab.h>
#ifdef CONFIG_SLUB
#include <linux/slub_def.h>
#else
#include <linux/slab_def.h>
#endif

#define CACHE_NAME_SIZE 32

// the key for the output summary
struct info_t {
    char name[CACHE_NAME_SIZE];
};

// the value of the output summary
struct val_t {
    u64 count;
    u64 size;
};

BPF_HASH(counts, struct info_t, struct val_t);

int kprobe__kmem_cache_alloc(struct pt_regs *ctx, struct kmem_cache *cachep)
{
    struct info_t info = {};
    const char *name = cachep->name;
    bpf_probe_read(&info.name, sizeof(info.name), name);

    struct val_t *valp, zero = {};
    valp = counts.lookup_or_init(&info, &zero);
    valp->count++;
    valp->size += cachep->size;

    return 0;
}
"""
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text)

print('Tracing... Output every %d secs. Hit Ctrl-C to end' % interval)

# output
exiting = 0
while 1:
    try:
        sleep(interval)
    except KeyboardInterrupt:
        exiting = 1

    # header
    if clear:
        call("clear")
    else:
        print()
    with open(loadavg) as stats:
        print("%-8s loadavg: %s" % (strftime("%H:%M:%S"), stats.read()))
    print("%-32s %6s %10s" % ("CACHE", "ALLOCS", "BYTES"))

    # by-TID output
    counts = b.get_table("counts")
    line = 0
    for k, v in reversed(sorted(counts.items(),
                                key=lambda counts: counts[1].size)):
        printb(b"%-32s %6d %10d" % (k.name, v.count, v.size))

        line += 1
        if line >= maxrows:
            break
    counts.clear()

    countdown -= 1
    if exiting or countdown == 0:
        print("Detaching...")
        exit()

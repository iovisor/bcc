#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# mctop   Memcached key operation analysis tool
#         For Linux, uses BCC, eBPF.
#
# USAGE: mctop.py  // FIXME detailed usage
#
# This uses in-kernel eBPF maps to trace and analyze key access rates and
# objects. This can help to spot hot keys, and tune memcached usage for
# performance.
#
# Copyright 2019 Shopify, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 17-Nov-2019   Dale Hamel   Created this.
# Insipried by the ruby tool of the same name by Marcus Barczak in 2012,
# see https://codeascraft.com/2012/12/13/mctop-a-tool-for-analyzing-memcache-get-traffic/

from __future__ import print_function
from time import sleep, strftime
from bcc import BPF, USDT, utils
import argparse
from subprocess import call

# arguments
examples = """examples:
    ./mctop -p PID          # memcached usage top, 1 second refresh
"""
# FIXME add sort-by functionality
parser = argparse.ArgumentParser(
    description="Memcached top key analysis",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", type=int, help="process id to attach to")
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
pid = args.pid

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>


#define MAX_STRING_LENGTH 80

// Must match python definitions
typedef enum {START, END, GET, ADD, SET, REPLACE, PREPEND, APPEND,
                       TOUCH, CAS, INCR, DECR, DELETE} memcached_op_t;
struct keyhit_t {
    char keystr[MAX_STRING_LENGTH];
};

struct value_t {
    u64 count;
    u64 bytecount;
};

BPF_HASH(keyhits, struct keyhit_t, struct value_t);


int trace_entry(struct pt_regs *ctx) {
    u64 keystr = 0, bytecount = 0;
    struct keyhit_t keyhit = {0};
    struct value_t *valp, zero = {};

    bpf_usdt_readarg(2, ctx, &keystr);
    bpf_usdt_readarg(4, ctx, &bytecount);

    bpf_probe_read(&keyhit.keystr, sizeof(keyhit.keystr), (void *)keystr);

    valp = keyhits.lookup_or_init(&keyhit, &zero);
    valp->count += 1;
    valp->bytecount = bytecount;

    return 0;
}

"""

if args.ebpf:
    print(bpf_text)
    exit()

usdt = USDT(pid=pid)
usdt.enable_probe(probe="command__set", fn_name="trace_entry") # FIXME use fully specified version, port this to python

bpf = BPF(text=bpf_text, usdt_contexts=[usdt])

print('Tracing... Output every %d secs. Hit Ctrl-C to end' % interval)

exiting = 0
while 1:
    try:
        sleep(interval)
    except KeyboardInterrupt:
        exiting = 1

    # header
    if clear:
        call("clear")

    print("%-30s %10s %10s" % ("MEMCACHED KEY", "CALLS", "OBJSIZE") )

    keyhits = bpf.get_table("keyhits")
    line = 0
    for k, v in keyhits.items(): # FIXME sort this

        # print line
        print("%-30s %10d %10d" % (k.keystr.decode('utf-8', 'replace'), v.count,
                                   v.bytecount) )

        line += 1
        if line >= maxrows:
            break
    #keyhits.clear()

    if exiting:
        print("Detaching...")
        exit()

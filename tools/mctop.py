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
# Inspired by the ruby tool of the same name by Marcus Barczak in 2012,
# see https://codeascraft.com/2012/12/13/mctop-a-tool-for-analyzing-memcache-get-traffic/
# see also https://github.com/tumblr/memkeys

from __future__ import print_function
from time import sleep, strftime, monotonic
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
#include <bcc/proto.h>


#define MAX_STRING_LENGTH 250

// Must match python definitions
typedef enum {START, END, GET, ADD, SET, REPLACE, PREPEND, APPEND,
                       TOUCH, CAS, INCR, DECR, DELETE} memcached_op_t;
struct keyhit_t {
    char keystr[MAX_STRING_LENGTH];
};

struct value_t {
    u64 count;
    u64 bytecount;
    u64 totalbytes;
    u64 keysize;
    u64 timestamp;
};

BPF_HASH(keyhits, struct keyhit_t, struct value_t);


int trace_entry(struct pt_regs *ctx) {
    u64 keystr = 0;
    int32_t bytecount = 0; // type is -4@%eax in stap notes, which is int32
    uint8_t keysize = 0; // type is 1@%cl, which should be uint8
    struct keyhit_t keyhit = {0};
    struct value_t *valp, zero = {};

    bpf_usdt_readarg(2, ctx, &keystr);
    bpf_usdt_readarg(3, ctx, &keysize);
    bpf_usdt_readarg(4, ctx, &bytecount);


    int bytesread = bpf_probe_read_str(&keyhit.keystr, sizeof(keyhit.keystr), (void *)keystr);

    // There is an issue where too many bytes can be (and often are) read
    // this may be a bug in memcached (if it doesn't null-terminate these), or
    // in these bcc helpers, and there is no elegant way to chomp this to the
    // correct size in bpf land yet.
    // see fix_keys below
    // see https://github.com/memcached/memcached/issues/576
    if (bytesread > (keysize+1))
      bpf_trace_printk("key: %s size: %d read bytes: %d\\n", keyhit.keystr, keysize, bytesread); // fixme - remove debugging

    valp = keyhits.lookup_or_init(&keyhit, &zero);
    valp->count += 1;
    valp->bytecount = bytecount;
    valp->keysize = keysize;
    valp->totalbytes += bytecount;
    valp->timestamp = bpf_ktime_get_ns();


    return 0;
}
"""

# Since it is possible that we read the keys incorrectly, we need to fix the
# hash keys and combine their values intelligently here, producing a new hash
# see https://github.com/memcached/memcached/issues/576
def fix_keys(bpf_map):

  new_map = {}

  for k,v in bpf_map.items():
      shortkey = k.keystr[:v.keysize].decode('utf-8', 'replace')

      if shortkey in new_map:
          new_map[shortkey].count += v.count
          new_map[shortkey].totalbytes += v.totalbytes
          if v.timestamp > new_map[shortkey].timestamp:
              new_map[shortkey].bytecount = v.bytecount
              new_map[shortkey].timestamp = v.timestamp
      else:
          new_map[shortkey] = v

  return new_map

if args.ebpf:
    print(bpf_text)
    exit()

usdt = USDT(pid=pid)
usdt.enable_probe(probe="command__set", fn_name="trace_entry") # FIXME use fully specified version, port this to python

bpf = BPF(text=bpf_text, usdt_contexts=[usdt])

print('Tracing... Output every %d secs. Hit Ctrl-C to end' % interval)

start = monotonic();
exiting = 0
while 1:
    try:
        sleep(interval)
    except KeyboardInterrupt:
        exiting = 1

    # header
    if clear:
        call("clear")


    print("%-30s %10s %10s %10s %10s %10s" % ("MEMCACHED KEY", "CALLS", "OBJSIZE", "REQ/SEC", "BW(kbps)", "TOTAL_BYTES") )
    keyhits = bpf.get_table("keyhits")
    line = 0
    interval = monotonic() - start;

    fixed_map = fix_keys(keyhits)
    for k, v in fixed_map.items(): # FIXME sort this

        cps = v.count / interval;
        bw  = (v.totalbytes / 1000) / interval;
        print("%-30s %10d %10d %10f %10f %10d" % (k, v.count,
                                   v.bytecount, cps, bw, v.totalbytes) )

        line += 1
        if line >= maxrows:
            break

    # fixme - implement purging mechanism that also resets start time
    #keyhits.clear()

    if exiting:
        print("Detaching...")
        exit()

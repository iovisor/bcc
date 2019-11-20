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
from subprocess import call
import argparse
import sys
import select
import tty
import termios

import enum # FIXME use or remove

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
parser.add_argument("-s", "--save", action="store_true",
    help="save eBPF map when dump command is issued")

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

# FIXME clean this up
args = parser.parse_args()
interval = int(args.interval)
countdown = int(args.count)
maxrows = int(args.maxrows)
clear = not int(args.noclear)
pid = args.pid

old_settings = termios.tcgetattr(sys.stdin)
sort_mode = "calls"
sort_ascending = True
exiting = 0
first_loop = True

sort_modes = {
    "C" : "calls",
    "S" : "size",
    "R" : "requests/sec",
    "B" : "bandwidth",
    "N" : "timestamp"
}

commands = {
    "T" : "toggle", # sorting by ascending / descending order
    "D" : "dump",   # clear eBPF maps and dump to disk (if set)
    "Q" : "quit"
}

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

    // see https://github.com/memcached/memcached/issues/576
    // ideally per https://github.com/iovisor/bcc/issues/1260 we should be able to
    // read just the size we need, but this doesn't seem possible and throws a
    // verifier error
    bpf_probe_read(&keyhit.keystr, sizeof(keyhit.keystr), (void *)keystr);

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
# A possible solution may be in flagging to the verifier that the size given
# by a usdt argument is less than the buffer size,
# see https://github.com/iovisor/bcc/issues/1260#issuecomment-406365168
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

def sort_output(unsorted_map, mode, sort_ascending):
    output = unsorted_map
    if mode == "calls":
        output = sorted(output.items(), key=lambda x: x[1].count)

    if sort_ascending:
        output = reversed(output)

    return output

# Set stdin to non-blocking reads so we can poll for chars
def readKey(interval):
    new_settings = termios.tcgetattr(sys.stdin)
    new_settings[3] = new_settings[3] & ~(termios.ECHO | termios.ICANON)
    tty.setcbreak(sys.stdin.fileno())
    if select.select([sys.stdin], [], [], 5) == ([sys.stdin], [], []):
        key = sys.stdin.read(1).lower()

        if key == 't':
            global sort_ascending
            sort_ascending = not sort_ascending
        if key == 'd':
            keyhits.clear() # FIXME save to file first

if args.ebpf:
    print(bpf_text)
    exit()

usdt = USDT(pid=pid)
usdt.enable_probe(probe="command__set", fn_name="trace_entry") # FIXME use fully specified version, port this to python
bpf = BPF(text=bpf_text, usdt_contexts=[usdt])

start = monotonic(); # FIXME would prefer monotonic_ns, if 3.7+

while 1:
    try:
        if not first_loop:
            readKey(interval)
        else:
            first_loop = False
    except KeyboardInterrupt:
        exiting = 1

    # header
    if clear:
        print("\033c", end="")

    print("%-30s %10s %10s %10s %10s %10s" % ("MEMCACHED KEY", "CALLS", "OBJSIZE", "REQ/SEC", "BW(kbps)", "TOTAL_BYTES") )
    keyhits = bpf.get_table("keyhits")
    line = 0
    interval = monotonic() - start;

    fixed_map = fix_keys(keyhits)
    sorted_map = sort_output(fixed_map, sort_mode, sort_ascending)
    for i, tup in enumerate(sorted_map): # FIXME sort this
        k = tup[0]; v = tup[1]

        cps = v.count / interval;
        bw  = (v.totalbytes / 1000) / interval;
        print("%-30s %10d %10d %10f %10f %10d" % (k, v.count,
                                   v.bytecount, cps, bw, v.totalbytes) )

        line += 1
        if line >= maxrows:
            break

    print((maxrows - line) * "\r\n")
    print("Sort mode: %s" % (sort_mode))
    print("\033[%d;%dH" % (0, 0))

    if exiting:
        print("Detaching...")
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        exit()

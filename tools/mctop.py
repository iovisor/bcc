#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# mctop   Memcached key operation analysis tool
#         For Linux, uses BCC, eBPF.
#
# USAGE: mctop.py  -p PID
#
# This uses in-kernel eBPF maps to trace and analyze key access rates and
# objects. This can help to spot hot keys, and tune memcached usage for
# performance.
#
# Copyright 2019 Shopify, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 20-Nov-2019   Dale Hamel   Created this.
# Inspired by the ruby tool of the same name by Marcus Barczak in 2012, see
# see also https://github.com/etsy/mctop
# see also https://github.com/tumblr/memkeys

from __future__ import print_function
from time import sleep, strftime, monotonic
from bcc import BPF, USDT, utils
from subprocess import call
from math import floor
import argparse
import sys
import select
import tty
import termios
import json

# FIXME better help
# arguments
examples = """examples:
    ./mctop -p PID          # memcached usage top, 1 second refresh
"""

parser = argparse.ArgumentParser(
    description="Memcached top key analysis",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", type=int, help="process id to attach to")
parser.add_argument(
    "-o",
    "--output",
    action="store",
    help="save map data to /top/OUTPUT.json if 'D' is issued to dump the map")

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
outfile = args.output
pid = args.pid

# Globals
exiting = 0
sort_mode = "C"
selected_line = 0
selected_page = 0
sort_ascending = True
bpf = None
sorted_output = []

SELECTED_LINE_UP = 1
SELECTED_LINE_DOWN = -1
SELECTED_LINE_PAGE_UP = maxrows * -1
SELECTED_LINE_PAGE_DOWN = maxrows
SELECTED_LINE_START = "start"
SELECTED_LINE_END = "end"

sort_modes = {
    "C": "calls",  # total calls to key
    "S": "size",  # latest size of key
    "R": "req/s",  # requests per second to this key
    "B": "bw",    # total bytes accesses on this key
    "N": "ts"     # timestamp of the latest access
}

commands = {
    "T": "t",  # sorting by ascending / descending order
    "W": "dump",   # clear eBPF maps and dump to disk (if set)
    "Q": "quit"    # exit mctop
}

# /typedef enum {START, END, GET, ADD, SET, REPLACE, PREPEND, APPEND,
#                       TOUCH, CAS, INCR, DECR, DELETE} memcached_op_t;

# FIXME have helper to generate per  type?
# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>

// #define FOREACH_MEMCACHED_CMD(MEMCACHED_CMD_INDEX) \
//         MEMCACHED_CMD_INDEX(MC_CMD_START)   \
//         MEMCACHED_CMD_INDEX(MC_CMD_END)   \
// 
//         MEMCACHED_CMD_INDEX(MC_GET)   \
//         MEMCACHED_CMD_INDEX(MC_ADD)   \
//         MEMCACHED_CMD_INDEX(MC_SET)   \
//         MEMCACHED_CMD_INDEX(MC_REPLACE)   \
//         MEMCACHED_CMD_INDEX(MC_PREPEND)   \
//         MEMCACHED_CMD_INDEX(MC_APPEND)   \
//         MEMCACHED_CMD_INDEX(MC_TOUCH)   \
//         MEMCACHED_CMD_INDEX(MC_CAS)   \
// 
//         MEMCACHED_CMD_INDEX(MC_INCR)   \
//         MEMCACHED_CMD_INDEX(MC_DECR)   \
//         MEMCACHED_CMD_INDEX(MC_DELETE)   \
// 
// 
// #define GENERATE_ENUM(ENUM) ENUM,
// #define GENERATE_STRING(STRING) #STRING,
// 
// // Generate enum for sem indices
// enum MEMCACHED_CMD_INDEX_ENUM {
//     FOREACH_MEMCACHED_CMD(GENERATE_ENUM)
// };

#define READ_MASK 0xff // allow buffer reads up to 256 bytes
struct keyhit_t {
    char keystr[READ_MASK];
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
    // as well as https://github.com/iovisor/bcc/issues/1260
    // we can convince the verifier the arbitrary read is safe using this
    // bitwise &, but only because our max buffer size happens to be 0xff,
    // which corresponds roughly to the the maximum key size
    bpf_probe_read(&keyhit.keystr, keysize & READ_MASK, (void *)keystr);

    valp = keyhits.lookup_or_init(&keyhit, &zero);
    valp->count++;
    valp->bytecount = bytecount;
    valp->keysize = keysize;
    valp->totalbytes += bytecount;
    valp->timestamp = bpf_ktime_get_ns();


    return 0;
}
"""

def sort_output(unsorted_map):
    global sort_mode
    global sort_ascending

    output = unsorted_map
    if sort_mode == "C":
        output = sorted(output.items(), key=lambda x: x[1]['count'])
    elif sort_mode == "S":
        output = sorted(output.items(), key=lambda x: x[1]['bytecount'])
    elif sort_mode == "R":
        output = sorted(output.items(), key=lambda x: x[1]['bandwidth'])
    elif sort_mode == "B":
        output = sorted(output.items(), key=lambda x: x[1]['cps'])
    elif sort_mode == "N":
        output = sorted(output.items(), key=lambda x: x[1]['timestamp'])

    if sort_ascending:
        output = reversed(output)

    return list(output)

# Set stdin to non-blocking reads so we can poll for chars

def change_selected_line(direction):
    global selected_line
    global selected_page
    global sorted_output
    global maxrows

    if direction == SELECTED_LINE_START:
        selected_line = 0
        selected_page = 0
        return
    elif direction == SELECTED_LINE_END:
        selected_line = len(sorted_output) -1
        selected_page = floor(selected_line / maxrows)
        return

    if direction > 0 and (selected_line + direction) >= len(sorted_output):
        selected_line = len(sorted_output) - 1
    elif direction < 0 and (selected_line + direction) <= 0:
        selected_line = 0
        selected_page = 0
    else:
        selected_line += direction
        selected_page = floor(selected_line / maxrows)

def readKey(interval):
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setcbreak(sys.stdin.fileno())
        if select.select([sys.stdin], [], [], 5) == ([sys.stdin], [], []):
            key = sys.stdin.read(1)
            global sort_mode

            if key.lower() == 't':
                global sort_ascending
                sort_ascending = not sort_ascending
            elif key.lower() == 'c':
                sort_mode = 'C'
            elif key.lower() == 's':
                sort_mode = 'S'
            elif key.lower() == 'r':
                sort_mode = 'R'
            elif key.lower() == 'b':
                sort_mode = 'B'
            elif key.lower() == 'n':
                sort_mode = 'N'
            elif key.lower() == 'j':
                change_selected_line(SELECTED_LINE_UP)
            elif key.lower() == 'k':
                change_selected_line(SELECTED_LINE_DOWN)
            elif key.lower() == 'u':
                change_selected_line(SELECTED_LINE_PAGE_UP)
            elif key.lower() == 'd':
                change_selected_line(SELECTED_LINE_PAGE_DOWN)
            elif key == 'g':
                change_selected_line(SELECTED_LINE_START)
            elif key == 'G':
                change_selected_line(SELECTED_LINE_END)
            elif key.lower() == 'w':
                 dump_map()
            elif key.lower() == 'q':
                print("QUITTING")
                global exiting
                exiting = 1
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def dump_map():
    global outfile
    global bpf
    global sorted_output
    global selected_line
    global selected_page

    print("DUMPING MAP")
    if outfile is not None:
        out = open('/tmp/%s.json' % outfile, 'w')
        json_str = json.dumps(sorted_output)
        out.write(json_str)
        out.close
    bpf.get_table("keyhits").clear()
    sorted_output.clear()
    selected_line = 0
    selected_page = 0


def run():
    global bpf
    global args
    global maxrows
    global exiting
    global ebpf_text
    global sorted_output

    if args.ebpf:
        print(bpf_text)
        exit()

    usdt = USDT(pid=pid)
    # FIXME use fully specified version, port this to python
    usdt.enable_probe(probe="command__set", fn_name="trace_entry")
    bpf = BPF(text=bpf_text, usdt_contexts=[usdt])

    old_settings = termios.tcgetattr(sys.stdin)
    first_loop = True

    start = monotonic()  # FIXME would prefer monotonic_ns, if 3.7+

    while True:
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

        print("%-30s %8s %8s %8s %8s %8s" % ("MEMCACHED KEY", "CALLS",
                                             "OBJSIZE", "REQ/S",
                                             "BW(kbps)", "TOTAL"))
        keyhits = bpf.get_table("keyhits")
        interval = monotonic() - start

        data_map = {}
        for k, v in keyhits.items():
            shortkey = k.keystr[:v.keysize].decode('utf-8', 'replace')
            data_map[shortkey] = {
                "count": v.count,
                "bytecount": v.bytecount,
                "totalbytes": v.totalbytes,
                "timestamp": v.timestamp,
                "cps": v.count / interval,
                "bandwidth": (v.totalbytes / 1000) / interval
            }

        sorted_output = sort_output(data_map)

        max_pages = floor(len(sorted_output) / maxrows)

        printed_lines = 0
        for i, tup in enumerate(sorted_output):  # FIXME sort this
            global selected_line
            global selected_page

            k = tup[0]
            v = tup[1]
            fmt_start = ""
            fmt_end   = ""

            page = floor(int(i) / int(maxrows))

            if page != selected_page:
                continue

            if i == selected_line:
                fmt_start = "\033[1;30;47m" # White background, black text
                fmt_end   = "\033[1;0;0;0m"

            print("%s%-30s %8d %8d %8f %8f %8d%s" % (fmt_start, k, v['count'], v['bytecount'],
                                                 v['cps'], v['bandwidth'],
                                                 v['totalbytes'], fmt_end) )
            printed_lines += 1

            if printed_lines >= maxrows:
                break


        print((maxrows - printed_lines) * "\r\n")
        sys.stdout.write("[Curr: %s/%s Opt: %s:%s|%s:%s|%s:%s|%s:%s|%s:%s]" %
                         (sort_mode,
                          "Asc" if sort_ascending else "Dsc",
                          'C', sort_modes['C'],
                          'S', sort_modes['S'],
                          'R', sort_modes['R'],
                          'B', sort_modes['B'],
                          'N', sort_modes['N']
                          ))

        sys.stdout.write("[%s:%s %s:%s %s:%s](%d/%d)" % (
            'T', commands['T'],
            'W', commands['W'],
            'Q', commands['Q'],
            selected_page + 1,
            max_pages + 1
        ))
        print("\033[%d;%dH" % (0, 0))

        if exiting:
            print("\033c", end="")
            exit()

run()

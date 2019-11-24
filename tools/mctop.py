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
clear = not int(args.noclear) # FIXME ensure it still works with clear disabled
outfile = args.output
pid = args.pid

# Globals
exiting = 0
sort_mode = "C"  # FIXME allow specifying at runtime
selected_line = 0
selected_page = 0
selected_key  = ""
start_time    = 0
sort_ascending = True
view_mode = 1 # 1 - index, 2 - histogram
match_key = None
bpf = None
histogram_bpf = None
sorted_output = []

SELECTED_LINE_UP = 1
SELECTED_LINE_DOWN = -1
SELECTED_LINE_PAGE_UP = maxrows * -1
SELECTED_LINE_PAGE_DOWN = maxrows
SELECTED_LINE_START = "start"
SELECTED_LINE_END = "end"

sort_modes = {
    "C": "calls", # total calls to key
    "S": "size",  # latest size of key
    "R": "req/s", # requests per second to this key
    "B": "bw",    # total bytes accesses on this key
    "L": "lat"    # aggregate call latency for this key
}

commands = {
    "I": "insp", # inspect the latency of commands processing this key
    "T": "tgl",  # toggle sorting by ascending / descending order
    "W": "dmp",  # clear eBPF maps and dump to disk (if set)
    "Q": "quit"  # exit mctop
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
    u64 latency;
};

BPF_HASH(keyhits, struct keyhit_t, struct value_t);
BPF_HASH(comm_start, int32_t, u64);
BPF_HASH(lastkey, u64, struct keyhit_t);
BPF_HISTOGRAM(cmd_latency);

// FIXME this should use bitwise & over the 4 x 64 bit ints of the char buffer
static inline bool match_key(const char * str) {
    DEFINE_KEY_MATCH

#ifdef KEY_MATCH
    char needle[] = "KEY_STRING";
    char haystack[sizeof(needle)];
    bpf_probe_read(&haystack, sizeof(haystack), (void *)str);
    for (int i = 0; i < sizeof(needle) - 1; ++i) {
            if (needle[i] != haystack[i]) {
                    return false;
            }
    }
    return true;

#else
    return false;
#endif // KEY_MATCH
}


int trace_command_start(struct pt_regs *ctx) {
    //u64 tid  = bpf_get_current_pid_tgid();
    int32_t conn_id = 0;
    bpf_usdt_readarg(1, ctx, &conn_id);
    u64 nsec = bpf_ktime_get_ns();
    comm_start.update(&conn_id, &nsec);
    return 0;
}

int trace_command_end(struct pt_regs *ctx) {

    struct keyhit_t *key;
    struct value_t *valp;
    int32_t conn_id = 0;
    u64 nsec = bpf_ktime_get_ns();
    bpf_usdt_readarg(1, ctx, &conn_id);

    u64 *start = comm_start.lookup(&conn_id);

    u64 lastkey_id = 0;

    if (start != NULL ) {
        u64 call_lat = nsec - *start;
        key = lastkey.lookup(&lastkey_id);

        if (key != NULL ) {
          valp = keyhits.lookup(key);
          if (valp) {
              valp->latency += call_lat;
          }
          DEFINE_KEY_MATCH
#ifdef KEY_MATCH
          if(match_key(key->keystr)) {
              bpf_trace_printk("KEY HIT on %s LAT: %d\\n", key->keystr, call_lat);
              cmd_latency.increment(bpf_log2l(call_lat));
          }
#endif // KEY_MATCH
        }
    }
    return 0;
}

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

    u64 lastkey_id = 0;
    lastkey.update(&lastkey_id, &keyhit);

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
    elif sort_mode == "L":
        output = sorted(output.items(), key=lambda x: x[1]['call_lat'])

    if sort_ascending:
        output = reversed(output)

    return list(output)

# Set stdin to non-blocking reads so we can poll for chars

def update_selected_key():
    global selected_key
    selected_key = sorted_output[selected_line][0]

def change_selected_line(direction):
    global selected_line
    global selected_page
    global sorted_output
    global maxrows

    if direction == SELECTED_LINE_START:
        selected_line = 0
        selected_page = 0
        update_selected_key()
        return
    elif direction == SELECTED_LINE_END:
        selected_line = len(sorted_output) -1
        selected_page = floor(selected_line / maxrows)
        update_selected_key()
        return

    if direction > 0 and (selected_line + direction) >= len(sorted_output):
        selected_line = len(sorted_output) - 1
    elif direction < 0 and (selected_line + direction) <= 0:
        selected_line = 0
        selected_page = 0
    else:
        selected_line += direction
        selected_page = floor(selected_line / maxrows)

    update_selected_key()

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
            elif key == 'C':
                sort_mode = 'C'
            elif key == 'S':
                sort_mode = 'S'
            elif key == 'R':
                sort_mode = 'R'
            elif key == 'B':
                sort_mode = 'B'
            elif key == 'L':
                sort_mode = 'L'
            elif key == 'H':
                global view_mode
                if view_mode == 2:
                    view_mode = 1
                else:
                    view_mode = 2
                if histogram_bpf == None:
                    histogram_init()
            elif key.lower() == 'j':
                change_selected_line(SELECTED_LINE_UP)
            elif key.lower() == 'k':
                change_selected_line(SELECTED_LINE_DOWN)
            elif key.lower() == 'h': # Reserved for shifting print of key
                pass
                #ROTATE_KEY_LEFT
            elif key.lower() == 'l': # Reserved for shifting print of key
                pass
                #ROTATE_KEY_RIGHT
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


# FIXME this should dump a full representation of the eBPF data in a reasonable
# schema
def dump_map():
    global outfile
    global bpf
    global sorted_output
    global selected_line
    global selected_page

    print("DUMPING DATA")
    if outfile is not None:
        out = open('/tmp/%s.json' % outfile, 'w')
        json_str = json.dumps(sorted_output)
        out.write(json_str)
        out.close
    bpf.get_table("keyhits").clear() # FIXME clear other maps
    sorted_output.clear()
    selected_line = 0
    selected_page = 0

# FIXME build from probe definition?
def build_probes(render_only):
    global bpf_text
    global usdt
    global pid

    rendered_text = bpf_text.replace("DEFINE_KEY_MATCH", "#define KEY_MATCH" if match_key != None else "") \
                             .replace("KEY_STRING", match_key if match_key != None else "")
    if render_only:
        print(rendered_text)
        exit()

    usdt = USDT(pid=pid)
    # FIXME use fully specified version, port this to python
    usdt.enable_probe(probe="command__set", fn_name="trace_entry")
    usdt.enable_probe(probe="process__command__start",
                                            fn_name="trace_command_start")
    usdt.enable_probe(probe="process__command__end",
                                            fn_name="trace_command_end")
    return BPF(text=rendered_text, usdt_contexts=[usdt])

def histogram_init():
    global match_key
    global selected_key
    global histogram_bpf

    global bpf
    bpf.cleanup() # FIXME need to make these clean each other up

    match_key = selected_key
    histogram_bpf = build_probes(False)


def print_histogram():
    global histogram_bpf
    global match_key

    print("Latency histogram for key %s" % (match_key))
    histogram_bpf["cmd_latency"].print_log2_hist("nsec")

def print_keylist():
    global bpf
    global maxrows
    global sorted_output
    global start_time
    global selected_key

    # FIXME better calculate the key width so that it can be shifted with h/l
    print("%-30s %8s %8s %8s %8s %8s" % ("MEMCACHED KEY", "CALLS",
                                         "OBJSIZE", "REQ/S",
                                         "BW(kbps)", "LAT(MS)"))
    keyhits = bpf.get_table("keyhits")
    interval = bpf.monotonic_time() - start_time

    data_map = {}
    for k, v in keyhits.items():
        shortkey = k.keystr[:v.keysize].decode('utf-8', 'replace')
        data_map[shortkey] = {
            "count": v.count,
            "bytecount": v.bytecount,
            "totalbytes": v.totalbytes,
            "timestamp": v.timestamp,
            "cps": v.count / interval,
            "bandwidth": (v.totalbytes / 1000) / interval,
            "latency": v.latency,
            "call_lat": (v.latency / v.count) / 1000,
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
                                             v['call_lat'], fmt_end) )
        printed_lines += 1

        if printed_lines >= maxrows:
            break

    print((maxrows - printed_lines) * "\r\n")
    print("[Selected key: %s ]" % selected_key )
    sys.stdout.write("[Curr: %s/%s Opt: %s:%s|%s:%s|%s:%s|%s:%s|%s:%s]" %
                     (sort_mode,
                      "Asc" if sort_ascending else "Dsc",
                      'C', sort_modes['C'],
                      'S', sort_modes['S'],
                      'R', sort_modes['R'],
                      'B', sort_modes['B'],
                      'L', sort_modes['L']
                      ))

    sys.stdout.write("[%s:%s %s:%s %s:%s](%d/%d)" % (
        'T', commands['T'],
        'W', commands['W'],
        'Q', commands['Q'],
        selected_page + 1,
        max_pages + 1
    ))

def run():
    global args
    global exiting
    global bpf
    global start_time
    global view_mode
    global interval


    bpf = build_probes(args.ebpf)
    first_loop = True

    start_time = bpf.monotonic_time()

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

        if view_mode == 1:
            print_keylist()
        elif view_mode == 2:
            print_histogram()
        print("\033[%d;%dH" % (0, 0))

        if exiting:
            print("\033c", end="")
            exit()

run()

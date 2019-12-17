#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# biolatency    Summarize block device I/O latency as a histogram.
#       For Linux, uses BCC, eBPF.
#
# USAGE: biolatency [-h] [-T] [-Q] [-m] [-D] [interval] [count]
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 20-Sep-2015   Brendan Gregg   Created this.
# 17-Dec-2019   Wesley Vaske  Extended bitesize.py and biolatency.py to be
#                             combined in a single script. Requires extension
#                             of BPF.Table to support additional struct keys

from __future__ import print_function
from bcc import BPF
import sys
from time import sleep
from datetime import datetime
import json
import types
import argparse

VERSION = "1.0"

# arguments
examples = """examples:
    ./jsonbiohists            # summarize block I/O latency as a histogram
    ./jsonbiohists 1 10       # print 1 second summaries, 10 times
    ./jsonbiohists -mT 1      # 1s summaries, milliseconds, and timestamps
    ./jsonbiohists -Q         # include OS queued time in I/O time
"""
parser = argparse.ArgumentParser(
    description="Summarize block device I/O latency as a histogram",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-Q", "--queued", action="store_true",
    help="include OS queued time in I/O time")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="millisecond histogram")
parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("-V", "--version", action="store_true",
                    help="Print version of this program.")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

if args.version:
    print(VERSION)
    exit()

countdown = int(args.count)
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

typedef struct disk_flag_key {
    char disk[DISK_NAME_LEN];
    u64 flags;
    u64 slot;
} disk_flag_key_t;

BPF_HASH(start, struct request *);
// The sizes here need to be larger as we're multiplying the 
//   total number of keys by the number of devices AND the 
//   number of IO flags. 1024 is likely too low for systems
//   with more than a few devices.
BPF_HISTOGRAM(latdist, disk_flag_key_t, 1024);
BPF_HISTOGRAM(sizedist, disk_flag_key_t, 1024);

// time block I/O
int trace_req_start(struct pt_regs *ctx, struct request *req)
{
    u64 ts = bpf_ktime_get_ns();
    start.update(&req, &ts);
    return 0;
}

// output
int trace_req_done(struct pt_regs *ctx, struct request *req)
{
    u64 *tsp, delta;

    // fetch timestamp and calculate delta
    tsp = start.lookup(&req);
    if (tsp == 0) {
        return 0;   // missed issue
    }
    delta = bpf_ktime_get_ns() - *tsp;
    delta /= 1000;

    // store as histogram
    disk_flag_key_t key = {.slot = bpf_log2l(delta)};
    key.flags = req->cmd_flags;
    void *__tmp = (void *)req->rq_disk->disk_name;
    bpf_probe_read(&key.disk, sizeof(key.disk), __tmp);
    latdist.increment(key);

    start.delete(&req);
    return 0;
}

// Get size data
int trace_req_size(struct pt_regs *ctx, struct request *req)
{
    // store as histogram
    disk_flag_key_t key = {.slot = bpf_log2l(req->__data_len / 1024)};
    key.flags = req->cmd_flags;
    void *__tmp = (void *)req->rq_disk->disk_name;
    bpf_probe_read(&key.disk, sizeof(key.disk), __tmp);
    sizedist.increment(key);
    return 0;
}
"""
# load BPF program
b = BPF(text=bpf_text)
if args.queued:
    b.attach_kprobe(event="blk_account_io_start", fn_name="trace_req_start")
else:
    if BPF.get_kprobe_functions(b'blk_start_request'):
        b.attach_kprobe(event="blk_start_request", fn_name="trace_req_start")
    b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")

b.attach_kprobe(event="blk_account_io_done", fn_name="trace_req_done")
b.attach_kprobe(event="blk_account_io_completion", fn_name="trace_req_size")

# see blk_fill_rwbs():
req_opf = {
    0: "Read",
    1: "Write",
    2: "Flush",
    3: "Discard",
    5: "SecureErase",
    6: "ZoneReset",
    7: "WriteSame",
    9: "WriteZeros"
}
REQ_OP_BITS = 8
REQ_OP_MASK = ((1 << REQ_OP_BITS) - 1)
REQ_SYNC = 1 << (REQ_OP_BITS + 3)
REQ_META = 1 << (REQ_OP_BITS + 4)
REQ_PRIO = 1 << (REQ_OP_BITS + 5)
REQ_NOMERGE = 1 << (REQ_OP_BITS + 6)
REQ_IDLE = 1 << (REQ_OP_BITS + 7)
REQ_FUA = 1 << (REQ_OP_BITS + 9)
REQ_RAHEAD = 1 << (REQ_OP_BITS + 11)
REQ_BACKGROUND = 1 << (REQ_OP_BITS + 12)
REQ_NOWAIT = 1 << (REQ_OP_BITS + 13)


def flags_print(flags):
    desc = ""
    # operation
    if flags & REQ_OP_MASK in req_opf:
        desc = req_opf[flags & REQ_OP_MASK]
    else:
        desc = "Unknown"
    # flags
    if flags & REQ_SYNC:
        desc = "Sync-" + desc
    if flags & REQ_META:
        desc = "Metadata-" + desc
    if flags & REQ_FUA:
        desc = "ForcedUnitAccess-" + desc
    if flags & REQ_PRIO:
        desc = "Priority-" + desc
    if flags & REQ_NOMERGE:
        desc = "NoMerge-" + desc
    if flags & REQ_IDLE:
        desc = "Idle-" + desc
    if flags & REQ_RAHEAD:
        desc = "ReadAhead-" + desc
    if flags & REQ_BACKGROUND:
        desc = "Background-" + desc
    if flags & REQ_NOWAIT:
        desc = "NoWait-" + desc
    return desc


# output
exiting = 0 if args.interval else 1
latdist = b.get_table("latdist")
sizedist = b.get_table("sizedist")

while True:
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = 1

    struct_keys = ['disk', 'flags', 'slot']
    key_decode_funcs = [
        lambda x: x,
        flags_print,
        lambda x: int(2 ** (x - 1))
    ]

    latdist.print_json(struct_keys=struct_keys,
                       key_decode_funcs=key_decode_funcs,
                       val_type="Latency (us)")
    latdist.clear()

    sizedist.print_json(struct_keys=struct_keys,
                        key_decode_funcs=key_decode_funcs,
                        val_type="Size (kB)")
    sizedist.clear()

    countdown -= 1
    if exiting or countdown == 0:
        exit()

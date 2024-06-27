#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# biolatency    Summarize block device I/O latency as a histogram.
#       For Linux, uses BCC, eBPF.
#
# USAGE: biolatency [-h] [-T] [-Q] [-m] [-D] [-F] [-e] [-j] [-d DISK] [interval] [count]
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 20-Sep-2015   Brendan Gregg   Created this.
# 31-Mar-2022   Rocky Xing      Added disk filter support.
# 01-Aug-2023   Jerome Marchand Added support for block tracepoints

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import ctypes as ct
import os

# arguments
examples = """examples:
    ./biolatency                    # summarize block I/O latency as a histogram
    ./biolatency 1 10               # print 1 second summaries, 10 times
    ./biolatency -mT 1              # 1s summaries, milliseconds, and timestamps
    ./biolatency -Q                 # include OS queued time in I/O time
    ./biolatency -D                 # show each disk device separately
    ./biolatency -F                 # show I/O flags separately
    ./biolatency -j                 # print a dictionary
    ./biolatency -e                 # show extension summary(total, average)
    ./biolatency -d sdc             # Trace sdc only
"""
parser = argparse.ArgumentParser(
    description="Summarize block device I/O latency as a histogram",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-Q", "--queued", action="store_true",
    help="include OS queued time in I/O time")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="millisecond histogram")
parser.add_argument("-D", "--disks", action="store_true",
    help="print a histogram per disk device")
parser.add_argument("-F", "--flags", action="store_true",
    help="print a histogram per set of I/O flags")
parser.add_argument("-e", "--extension", action="store_true",
    help="summarize average/total value")
parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
parser.add_argument("-j", "--json", action="store_true",
    help="json output")
parser.add_argument("-d", "--disk", type=str,
    help="Trace this disk only")

args = parser.parse_args()
countdown = int(args.count)
debug = 0

if args.flags and args.disks:
    print("ERROR: can only use -D or -F. Exiting.")
    exit()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

typedef struct disk_key {
    dev_t dev;
    u64 slot;
} disk_key_t;

typedef struct flag_key {
    u64 flags;
    u64 slot;
} flag_key_t;

typedef struct ext_val {
    u64 total;
    u64 count;
} ext_val_t;

struct tp_args {
    u64 __unused__;
    dev_t dev;
    sector_t sector;
    unsigned int nr_sector;
    unsigned int bytes;
    char rwbs[8];
    char comm[16];
    char cmd[];
};

struct start_key {
    dev_t dev;
    u32 _pad;
    sector_t sector;
    CMD_FLAGS
};

BPF_HASH(start, struct start_key);
STORAGE

static dev_t ddevt(struct gendisk *disk) {
    return (disk->major  << 20) | disk->first_minor;
}

// time block I/O
static int __trace_req_start(struct start_key key)
{
    DISK_FILTER

    u64 ts = bpf_ktime_get_ns();
    start.update(&key, &ts);
    return 0;
}

int trace_req_start(struct pt_regs *ctx, struct request *req)
{
    struct start_key key = {
        .dev = ddevt(req->__RQ_DISK__),
        .sector = req->__sector
    };

    SET_FLAGS

    return __trace_req_start(key);
}

int trace_req_start_tp(struct tp_args *args)
{
    struct start_key key = {
        .dev = args->dev,
        .sector = args->sector
    };

    return __trace_req_start(key);
}

// output
static int __trace_req_done(struct start_key key)
{
    u64 *tsp, delta;

    // fetch timestamp and calculate delta
    tsp = start.lookup(&key);
    if (tsp == 0) {
        return 0;   // missed issue
    }
    delta = bpf_ktime_get_ns() - *tsp;

    FACTOR

    // store as histogram
    STORE

    start.delete(&key);
    return 0;
}

int trace_req_done(struct pt_regs *ctx, struct request *req)
{
    struct start_key key = {
        .dev = ddevt(req->__RQ_DISK__),
        .sector = req->__sector
    };

    SET_FLAGS

    return __trace_req_done(key);
}

int trace_req_done_tp(struct tp_args *args)
{
    struct start_key key = {
        .dev = args->dev,
        .sector = args->sector
    };

    return __trace_req_done(key);
}
"""

# code substitutions
if args.milliseconds:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000000;')
    label = "msecs"
else:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000;')
    label = "usecs"

storage_str = ""
store_str = ""
if args.disks:
    storage_str += "BPF_HISTOGRAM(dist, disk_key_t);"
    disks_str = """
    disk_key_t dkey = {};
    dkey.dev = key.dev;
    dkey.slot = bpf_log2l(delta);
    dist.atomic_increment(dkey);
    """
    store_str += disks_str
elif args.flags:
    storage_str += "BPF_HISTOGRAM(dist, flag_key_t);"
    store_str += """
    flag_key_t fkey = {.slot = bpf_log2l(delta)};
    fkey.flags = key.flags;
    dist.atomic_increment(fkey);
    """
else:
    storage_str += "BPF_HISTOGRAM(dist);"
    store_str += "dist.atomic_increment(bpf_log2l(delta));"

if args.disk is not None:
    disk_path = os.path.join('/dev', args.disk)
    if not os.path.exists(disk_path):
        print("no such disk '%s'" % args.disk)
        exit(1)

    stat_info = os.stat(disk_path)
    dev = os.major(stat_info.st_rdev) << 20 | os.minor(stat_info.st_rdev)

    disk_filter_str = """
    if(key.dev != %s) {
        return 0;
    }
    """ % (dev)

    bpf_text = bpf_text.replace('DISK_FILTER', disk_filter_str)
else:
    bpf_text = bpf_text.replace('DISK_FILTER', '')

if args.extension:
    storage_str += "BPF_ARRAY(extension, ext_val_t, 1);"
    store_str += """
    u32 index = 0;
    ext_val_t *ext_val = extension.lookup(&index);
    if (ext_val) {
        lock_xadd(&ext_val->total, delta);
        lock_xadd(&ext_val->count, 1);
    }
    """

bpf_text = bpf_text.replace("STORAGE", storage_str)
bpf_text = bpf_text.replace("STORE", store_str)
if BPF.kernel_struct_has_field(b'request', b'rq_disk') == 1:
    bpf_text = bpf_text.replace('__RQ_DISK__', 'rq_disk')
else:
    bpf_text = bpf_text.replace('__RQ_DISK__', 'q->disk')
if args.flags:
    bpf_text = bpf_text.replace('CMD_FLAGS', 'u64 flags;')
    bpf_text = bpf_text.replace('SET_FLAGS', 'key.flags = req->cmd_flags;')
else:
    bpf_text = bpf_text.replace('CMD_FLAGS', '')
    bpf_text = bpf_text.replace('SET_FLAGS', '')

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# load BPF program
b = BPF(text=bpf_text)
if args.queued:
    if BPF.tracepoint_exists("block", "block_io_start"):
        b.attach_tracepoint(tp="block:block_io_start", fn_name="trace_req_start_tp")
    elif BPF.get_kprobe_functions(b'__blk_account_io_start'):
        b.attach_kprobe(event="__blk_account_io_start", fn_name="trace_req_start")
    elif BPF.get_kprobe_functions(b'blk_account_io_start'):
        b.attach_kprobe(event="blk_account_io_start", fn_name="trace_req_start")
    elif BPF.tracepoint_exists("block", "block_bio_queue"):
        b.attach_tracepoint(tp="block:block_bio_queue", fn_name="trace_req_start_tp")
    else:
        if args.flags:
            # Some flags are accessible in the rwbs field (RAHEAD, SYNC and META)
            # but other aren't. Disable the -F option for tracepoint for now.
            print("ERROR: blk_account_io_start probe not available. Can't use -F.")
            exit()
else:
    if BPF.get_kprobe_functions(b'blk_start_request'):
        b.attach_kprobe(event="blk_start_request", fn_name="trace_req_start")
    b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")

if BPF.tracepoint_exists("block", "block_io_done"):
    b.attach_tracepoint(tp="block:block_io_done", fn_name="trace_req_done_tp")
elif BPF.get_kprobe_functions(b'__blk_account_io_done'):
    b.attach_kprobe(event="__blk_account_io_done", fn_name="trace_req_done")
elif BPF.get_kprobe_functions(b'blk_account_io_done'):
    b.attach_kprobe(event="blk_account_io_done", fn_name="trace_req_done")
elif BPF.tracepoint_exists("block", "block_rq_complete"):
    b.attach_tracepoint(tp="block:block_rq_complete", fn_name="trace_req_done_tp")
else:
    if args.flags:
        print("ERROR: blk_account_io_done probe not available. Can't use -F.")
        exit()


if not args.json:
    print("Tracing block device I/O... Hit Ctrl-C to end.")

# cache disk major,minor -> diskname
diskstats = "/proc/diskstats"
disklookup = {}
with open(diskstats) as stats:
    for line in stats:
        a = line.split()
        disklookup[a[0] + "," + a[1]] = a[2]

def disk_print(d):
    major = d >> 20
    minor = d & ((1 << 20) - 1)

    disk = str(major) + "," + str(minor)
    if disk in disklookup:
        diskname = disklookup[disk]
    else:
        diskname = "?"

    return diskname

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
dist = b.get_table("dist")
if args.extension:
    extension = b.get_table("extension")
while (1):
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = 1

    print()
    if args.json:
        if args.timestamp:
            print("%-8s\n" % strftime("%H:%M:%S"), end="")

        if args.flags:
            dist.print_json_hist(label, "flags", flags_print)
        else:
            dist.print_json_hist(label, "disk", disk_print)

    else:
        if args.timestamp:
            print("%-8s\n" % strftime("%H:%M:%S"), end="")

        if args.flags:
            dist.print_log2_hist(label, "flags", flags_print)
        else:
            dist.print_log2_hist(label, "disk", disk_print)
        if args.extension:
            total = extension[0].total
            count = extension[0].count
            if count > 0:
                print("\navg = %ld %s, total: %ld %s, count: %ld\n" %
                      (total / count, label, total, label, count))
            extension.clear()

    dist.clear()

    countdown -= 1
    if exiting or countdown == 0:
        exit()

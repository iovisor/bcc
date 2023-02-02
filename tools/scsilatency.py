#!/usr/bin/python
# SPDX-License-Identifier: <SPDX License Expression>
# @lint-avoid-python-3-compatibility-imports
#
# scsilatency    Summarize SCSI layer I/O latency as a histogram.
#       For Linux, uses BCC, eBPF.
#
# USAGE: scsilatency [-h] [-T] [-Q] [-m] [-D] [-e] [interval] [count]
#
# Copyright (c) 10-Oct-2022, Samsung Electronics.  All rights reserved.
# This source code is licensed under the Apache License, Version 2.0
#
# Written by Weibang Liu<weibang6.liu@samsung.com>.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import ctypes as ct

# arguments
examples = """examples:
    ./scsilatency            # summarize SCSI layer I/O latency as a histogram
    ./scsilatency 1 10       # print 1 second summaries, 10 times
    ./scsilatency -mT 1      # 1s summaries, milliseconds, and timestamps
    ./scsilatency -D         # show each disk device separately
    ./scsilatency -F         # show I/O flags separately
    ./scsilatency -j         # print a dictionary
    ./scsilatency -e         # show extension summary(total, average)
"""
parser = argparse.ArgumentParser(
    description="Summarize SCSI layer I/O latency as a histogram",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
                    help="include timestamp on output")
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

args = parser.parse_args()
countdown = int(args.count)
debug = 0

if args.flags and args.disks:
    print("ERROR: can only use -D or -F. Exiting.")
    exit()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <scsi/scsi_cmnd.h>

typedef struct disk_key {
    char disk[DISK_NAME_LEN];
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

BPF_HASH(start, struct request *);
STORAGE

// start time of SCSI I/O
int trace_req_start(struct pt_regs *ctx, struct scsi_cmnd *cmd)
{
    struct request *req = cmd->request;

    u64 ts = bpf_ktime_get_ns();
    start.update(&req, &ts);
    return 0;
}

// output
int trace_req_done(struct pt_regs *ctx, struct scsi_cmnd *cmd)
{
    u64 *tsp, delta;
    struct request *req = cmd->request;

    // fetch timestamp and calculate delta
    tsp = start.lookup(&req);
    if (tsp == 0) {
        return 0;   // missed issue
    }
    delta = bpf_ktime_get_ns() - *tsp;

    EXTENSION

    FACTOR

    // store as histogram
    STORE

    start.delete(&req);
    return 0;
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
    store_str += """
    disk_key_t key = {.slot = bpf_log2l(delta)};
    void *__tmp = (void *)req->rq_disk->disk_name;
    bpf_probe_read(&key.disk, sizeof(key.disk), __tmp);
    dist.increment(key);
    """
elif args.flags:
    storage_str += "BPF_HISTOGRAM(dist, flag_key_t);"
    store_str += """
    flag_key_t key = {.slot = bpf_log2l(delta)};

    #ifdef REQ_WRITE
        key.flags = !!(req->cmd_flags & REQ_WRITE);
    #elif defined(REQ_OP_SHIFT)
        key.flags = !!((req->cmd_flags >> REQ_OP_SHIFT) == REQ_OP_WRITE);
    #else
        key.flags = !!((req->cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);
    #endif

    dist.increment(key);
    """
else:
    storage_str += "BPF_HISTOGRAM(dist);"
    store_str += "dist.increment(bpf_log2l(delta));"

if args.extension:
    storage_str += "BPF_ARRAY(extension, ext_val_t, 1);"
    bpf_text = bpf_text.replace('EXTENSION', """
    u32 index = 0;
    ext_val_t *ext_val = extension.lookup(&index);
    if (ext_val) {
        lock_xadd(&ext_val->total, delta);
        lock_xadd(&ext_val->count, 1);
    }
    """)
else:
    bpf_text = bpf_text.replace('EXTENSION', '')
bpf_text = bpf_text.replace("STORAGE", storage_str)
bpf_text = bpf_text.replace("STORE", store_str)

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# load BPF program
b = BPF(text=bpf_text)
if BPF.get_kprobe_functions(b'scsi_init_io'):
    b.attach_kprobe(event="scsi_init_io", fn_name="trace_req_start")
else:
    b.attach_kprobe(event="scsi_alloc_sgtables", fn_name="trace_req_start")
if BPF.get_kprobe_functions(b'scsi_mq_done'):
    b.attach_kprobe(event="scsi_mq_done", fn_name="trace_req_done")

if not args.json:
    print("Tracing SCSI layer I/O... Hit Ctrl-C to end.")


def flags_print(flags):
    desc = ""
    if flags == 1:
        desc = "Write"
    else:
        desc = "Read"

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
            dist.print_json_hist(label)

    else:
        if args.timestamp:
            print("%-8s\n" % strftime("%H:%M:%S"), end="")

        if args.flags:
            dist.print_log2_hist(label, "flags", flags_print)
        else:
            dist.print_log2_hist(label, "disk")
        if args.extension:
            total = extension[0].total
            counts = extension[0].count
            if counts > 0:
                if label == 'msecs':
                    total /= 1000000
                elif label == 'usecs':
                    total /= 1000
                avg = total / counts
                print("\navg = %ld %s, total: %ld %s, count: %ld\n" %
                      (total / counts, label, total, label, counts))
            extension.clear()

    dist.clear()

    countdown -= 1
    if exiting or countdown == 0:
        exit()

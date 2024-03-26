#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# biotop  block device (disk) I/O by process.
#         For Linux, uses BCC, eBPF.
#
# USAGE: biotop.py [-h] [-C] [-r MAXROWS] [-p PID] [interval] [count]
#
# This uses in-kernel eBPF maps to cache process details (PID and comm) by I/O
# request, as well as a starting timestamp for calculating I/O latency.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 06-Feb-2016   Brendan Gregg   Created this.
# 17-Mar-2022   Rocky Xing      Added PID filter support.
# 01-Aug-2023   Jerome Marchand Added support for block tracepoints

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
from subprocess import call

# arguments
examples = """examples:
    ./biotop            # block device I/O top, 1 second refresh
    ./biotop -C         # don't clear the screen
    ./biotop -p 181     # only trace PID 181
    ./biotop 5          # 5 second summaries
    ./biotop 5 10       # 5 second summaries, 10 times only
"""
parser = argparse.ArgumentParser(
    description="Block device (disk) I/O by process",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-C", "--noclear", action="store_true",
    help="don't clear the screen")
parser.add_argument("-r", "--maxrows", default=20,
    help="maximum rows to print, default 20")
parser.add_argument("-p", "--pid", type=int, metavar="PID",
    help="trace this PID only")
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

# linux stats
loadavg = "/proc/loadavg"
diskstats = "/proc/diskstats"

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

// for saving the timestamp, __data_len, and cmd_flags of each request
struct start_req_t {
    u64 ts;
    u64 data_len;
    u64 cmd_flags;
};

// for saving process info by request
struct who_t {
    u32 pid;
    char name[TASK_COMM_LEN];
};

// the key for the output summary
struct info_t {
    u32 pid;
    int rwflag;
    int major;
    int minor;
    char name[TASK_COMM_LEN];
};

// the value of the output summary
struct val_t {
    u64 bytes;
    u64 us;
    u32 io;
};

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

struct hash_key {
    dev_t dev;
    u32 _pad;
    sector_t sector;
};

BPF_HASH(start, struct hash_key, struct start_req_t);
BPF_HASH(whobyreq, struct hash_key, struct who_t);
BPF_HASH(counts, struct info_t, struct val_t);

static dev_t ddevt(struct gendisk *disk) {
    return (disk->major  << 20) | disk->first_minor;
}

// cache PID and comm by-req
static int __trace_pid_start(struct hash_key key)
{
    struct who_t who;
    u32 pid;

    if (bpf_get_current_comm(&who.name, sizeof(who.name)) == 0) {
        pid = bpf_get_current_pid_tgid() >> 32;
        if (FILTER_PID)
            return 0;

        who.pid = pid;
        whobyreq.update(&key, &who);
    }

    return 0;
}

int trace_pid_start(struct pt_regs *ctx, struct request *req)
{
    struct hash_key key = {
        .dev = ddevt(req->__RQ_DISK__),
        .sector = req->__sector
    };

    return __trace_pid_start(key);
}

int trace_pid_start_tp(struct tp_args *args)
{
    struct hash_key key = {
        .dev = args->dev,
        .sector = args->sector
    };

    return __trace_pid_start(key);
}

// time block I/O
int trace_req_start(struct pt_regs *ctx, struct request *req)
{
    struct hash_key key = {
        .dev = ddevt(req->__RQ_DISK__),
        .sector = req->__sector
    };
    struct start_req_t start_req = {
        .ts = bpf_ktime_get_ns(),
        .data_len = req->__data_len,
        .cmd_flags = req->cmd_flags
    };
    start.update(&key, &start_req);
    return 0;
}

// output
static int __trace_req_completion(struct hash_key key)
{
    struct start_req_t *startp;

    // fetch timestamp and calculate delta
    startp = start.lookup(&key);
    if (startp == 0) {
        return 0;    // missed tracing issue
    }

    struct who_t *whop;
    u32 pid;

    whop = whobyreq.lookup(&key);
    pid = whop != 0 ? whop->pid : 0;
    if (FILTER_PID) {
        start.delete(&key);
        if (whop != 0) {
            whobyreq.delete(&key);
        }
        return 0;
    }

    struct val_t *valp, zero = {};
    u64 delta_us = (bpf_ktime_get_ns() - startp->ts) / 1000;

    // setup info_t key
    struct info_t info = {};
    info.major = key.dev >> 20;
    info.minor = key.dev & ((1 << 20) - 1);
/*
 * The following deals with a kernel version change (in mainline 4.7, although
 * it may be backported to earlier kernels) with how block request write flags
 * are tested. We handle both pre- and post-change versions here. Please avoid
 * kernel version tests like this as much as possible: they inflate the code,
 * test, and maintenance burden.
 */
#ifdef REQ_WRITE
    info.rwflag = !!(startp->cmd_flags & REQ_WRITE);
#elif defined(REQ_OP_SHIFT)
    info.rwflag = !!((startp->cmd_flags >> REQ_OP_SHIFT) == REQ_OP_WRITE);
#else
    info.rwflag = !!((startp->cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);
#endif

    if (whop == 0) {
        // missed pid who, save stats as pid 0
        valp = counts.lookup_or_try_init(&info, &zero);
    } else {
        info.pid = whop->pid;
        __builtin_memcpy(&info.name, whop->name, sizeof(info.name));
        valp = counts.lookup_or_try_init(&info, &zero);
    }

    if (valp) {
        // save stats
        valp->us += delta_us;
        valp->bytes += startp->data_len;
        valp->io++;
    }

    start.delete(&key);
    whobyreq.delete(&key);

    return 0;
}

int trace_req_completion(struct pt_regs *ctx, struct request *req)
{
    struct hash_key key = {
        .dev = ddevt(req->__RQ_DISK__),
        .sector = req->__sector
    };

    return __trace_req_completion(key);
}

int trace_req_completion_tp(struct tp_args *args)
{
    struct hash_key key = {
        .dev = args->dev,
        .sector = args->sector
    };

    return __trace_req_completion(key);
}
"""

if args.ebpf:
    print(bpf_text)
    exit()

if BPF.kernel_struct_has_field(b'request', b'rq_disk') == 1:
    bpf_text = bpf_text.replace('__RQ_DISK__', 'rq_disk')
else:
    bpf_text = bpf_text.replace('__RQ_DISK__', 'q->disk')

if args.pid is not None:
    bpf_text = bpf_text.replace('FILTER_PID', 'pid != %d' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER_PID', '0')

b = BPF(text=bpf_text)
if BPF.tracepoint_exists("block", "block_io_start"):
    b.attach_tracepoint(tp="block:block_io_start", fn_name="trace_pid_start_tp")
elif BPF.get_kprobe_functions(b'__blk_account_io_start'):
    b.attach_kprobe(event="__blk_account_io_start", fn_name="trace_pid_start")
elif BPF.get_kprobe_functions(b'blk_account_io_start'):
    b.attach_kprobe(event="blk_account_io_start", fn_name="trace_pid_start")
else:
    print("ERROR: No found any block io start probe/tp.")
    exit()

if BPF.get_kprobe_functions(b'blk_start_request'):
    b.attach_kprobe(event="blk_start_request", fn_name="trace_req_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")

if BPF.tracepoint_exists("block", "block_io_done"):
    b.attach_tracepoint(tp="block:block_io_done", fn_name="trace_req_completion_tp")
elif BPF.get_kprobe_functions(b'__blk_account_io_done'):
    b.attach_kprobe(event="__blk_account_io_done", fn_name="trace_req_completion")
elif BPF.get_kprobe_functions(b'blk_account_io_done'):
    b.attach_kprobe(event="blk_account_io_done", fn_name="trace_req_completion")
else:
    print("ERROR: No found any block io done probe/tp.")
    exit()

# check whether hash table batch ops is supported
htab_batch_ops = True if BPF.kernel_struct_has_field(b'bpf_map_ops',
        b'map_lookup_and_delete_batch') == 1 else False

print('Tracing... Output every %d secs. Hit Ctrl-C to end' % interval)

# cache disk major,minor -> diskname
disklookup = {}
with open(diskstats) as stats:
    for line in stats:
        a = line.split()
        disklookup[a[0] + "," + a[1]] = a[2]

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
    print("%-7s %-16s %1s %-3s %-3s %-8s %5s %7s %6s" % ("PID", "COMM",
        "D", "MAJ", "MIN", "DISK", "I/O", "Kbytes", "AVGms"))

    # by-PID output
    counts = b.get_table("counts")
    line = 0
    for k, v in reversed(sorted(counts.items_lookup_and_delete_batch()
                                if htab_batch_ops else counts.items(),
                                key=lambda counts: counts[1].bytes)):

        # lookup disk
        disk = str(k.major) + "," + str(k.minor)
        if disk in disklookup:
            diskname = disklookup[disk]
        else:
            diskname = "?"

        # print line
        avg_ms = (float(v.us) / 1000) / v.io
        print("%-7d %-16s %1s %-3d %-3d %-8s %5s %7s %6.2f" % (k.pid,
            k.name.decode('utf-8', 'replace'), "W" if k.rwflag else "R",
            k.major, k.minor, diskname, v.io, v.bytes / 1024, avg_ms))

        line += 1
        if line >= maxrows:
            break

    if not htab_batch_ops:
        counts.clear()

    countdown -= 1
    if exiting or countdown == 0:
        print("Detaching...")
        exit()

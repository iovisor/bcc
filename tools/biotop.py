#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# biotop  block device (disk) I/O by process.
#         For Linux, uses BCC, eBPF.
#
# USAGE: biotop.py [-h] [-C] [-r MAXROWS] [interval] [count]
#
# This uses in-kernel eBPF maps to cache process details (PID and comm) by I/O
# request, as well as a starting timestamp for calculating I/O latency.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 06-Feb-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import signal
from subprocess import call

# arguments
examples = """examples:
    ./biotop            # block device I/O top, 1 second refresh
    ./biotop -C         # don't clear the screen
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

# signal handler
def signal_ignore(signal, frame):
    print()

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

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

BPF_HASH(start, struct request *);
BPF_HASH(whobyreq, struct request *, struct who_t);
BPF_HASH(counts, struct info_t, struct val_t);

// cache PID and comm by-req
int trace_pid_start(struct pt_regs *ctx, struct request *req)
{
    struct who_t who = {};

    if (bpf_get_current_comm(&who.name, sizeof(who.name)) == 0) {
        who.pid = bpf_get_current_pid_tgid();
        whobyreq.update(&req, &who);
    }

    return 0;
}

// time block I/O
int trace_req_start(struct pt_regs *ctx, struct request *req)
{
    u64 ts;

    ts = bpf_ktime_get_ns();
    start.update(&req, &ts);

    return 0;
}

// output
int trace_req_completion(struct pt_regs *ctx, struct request *req)
{
    u64 *tsp;

    // fetch timestamp and calculate delta
    tsp = start.lookup(&req);
    if (tsp == 0) {
        return 0;    // missed tracing issue
    }

    struct who_t *whop;
    struct val_t *valp, zero = {};
    u64 delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;

    // setup info_t key
    struct info_t info = {};
    info.major = req->rq_disk->major;
    info.minor = req->rq_disk->first_minor;
/*
 * The following deals with a kernel version change (in mainline 4.7, although
 * it may be backported to earlier kernels) with how block request write flags
 * are tested. We handle both pre- and post-change versions here. Please avoid
 * kernel version tests like this as much as possible: they inflate the code,
 * test, and maintenance burden.
 */
#ifdef REQ_WRITE
    info.rwflag = !!(req->cmd_flags & REQ_WRITE);
#elif defined(REQ_OP_SHIFT)
    info.rwflag = !!((req->cmd_flags >> REQ_OP_SHIFT) == REQ_OP_WRITE);
#else
    info.rwflag = !!((req->cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);
#endif

    whop = whobyreq.lookup(&req);
    if (whop == 0) {
        // missed pid who, save stats as pid 0
        valp = counts.lookup_or_init(&info, &zero);
    } else {
        info.pid = whop->pid;
        __builtin_memcpy(&info.name, whop->name, sizeof(info.name));
        valp = counts.lookup_or_init(&info, &zero);
    }

    // save stats
    valp->us += delta_us;
    valp->bytes += req->__data_len;
    valp->io++;

    start.delete(&req);
    whobyreq.delete(&req);

    return 0;
}
"""

if args.ebpf:
    print(bpf_text)
    exit()

b = BPF(text=bpf_text)
b.attach_kprobe(event="blk_account_io_start", fn_name="trace_pid_start")
b.attach_kprobe(event="blk_start_request", fn_name="trace_req_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")
b.attach_kprobe(event="blk_account_io_completion",
    fn_name="trace_req_completion")

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
    print("%-6s %-16s %1s %-3s %-3s %-8s %5s %7s %6s" % ("PID", "COMM",
        "D", "MAJ", "MIN", "DISK", "I/O", "Kbytes", "AVGms"))

    # by-PID output
    counts = b.get_table("counts")
    line = 0
    for k, v in reversed(sorted(counts.items(),
                                key=lambda counts: counts[1].bytes)):

        # lookup disk
        disk = str(k.major) + "," + str(k.minor)
        if disk in disklookup:
            diskname = disklookup[disk]
        else:
            diskname = "?"

        # print line
        avg_ms = (float(v.us) / 1000) / v.io
        print("%-6d %-16s %1s %-3d %-3d %-8s %5s %7s %6.2f" % (k.pid,
            k.name.decode('utf-8', 'replace'), "W" if k.rwflag else "R",
            k.major, k.minor, diskname, v.io, v.bytes / 1024, avg_ms))

        line += 1
        if line >= maxrows:
            break
    counts.clear()

    countdown -= 1
    if exiting or countdown == 0:
        print("Detaching...")
        exit()

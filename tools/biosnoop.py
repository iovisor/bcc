#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# biosnoop  Trace block device I/O and print details including issuing PID.
#           For Linux, uses BCC, eBPF.
#
# This uses in-kernel eBPF maps to cache process details (PID and comm) by I/O
# request, as well as a starting timestamp for calculating I/O latency.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 16-Sep-2015   Brendan Gregg   Created this.
# 11-Feb-2016   Allan McAleavy  updated for BPF_PERF_OUTPUT
# 21-Jun-2022   Rocky Xing      Added disk filter support.
# 13-Oct-2022   Rocky Xing      Added support for displaying block I/O pattern.

from __future__ import print_function
from bcc import BPF
import argparse
import os

# arguments
examples = """examples:
    ./biosnoop           # trace all block I/O
    ./biosnoop -Q        # include OS queued time
    ./biosnoop -d sdc    # trace sdc only
    ./biosnoop -P        # display block I/O pattern
"""
parser = argparse.ArgumentParser(
    description="Trace block I/O",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-Q", "--queue", action="store_true",
    help="include OS queued time")
parser.add_argument("-d", "--disk", type=str,
    help="trace this disk only")
parser.add_argument("-P", "--pattern", action="store_true",
    help="display block I/O pattern (sequential or random)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>
"""

if args.pattern:
    bpf_text += "#define INCLUDE_PATTERN\n"

bpf_text += """
// for saving the timestamp and __data_len of each request
struct start_req_t {
    u64 ts;
    u64 data_len;
};

struct val_t {
    u64 ts;
    u32 pid;
    char name[TASK_COMM_LEN];
};

#ifdef INCLUDE_PATTERN
struct sector_key_t {
    u32 dev_major;
    u32 dev_minor;
};

enum bio_pattern {
    UNKNOWN,
    SEQUENTIAL,
    RANDOM,
};
#endif

struct data_t {
    u32 pid;
    u64 rwflag;
    u64 delta;
    u64 qdelta;
    u64 sector;
    u64 len;
#ifdef INCLUDE_PATTERN
    enum bio_pattern pattern;
#endif
    u64 ts;
    char disk_name[DISK_NAME_LEN];
    char name[TASK_COMM_LEN];
};

#ifdef INCLUDE_PATTERN
BPF_HASH(last_sectors, struct sector_key_t, u64);
#endif

BPF_HASH(start, struct request *, struct start_req_t);
BPF_HASH(infobyreq, struct request *, struct val_t);
BPF_PERF_OUTPUT(events);

// cache PID and comm by-req
int trace_pid_start(struct pt_regs *ctx, struct request *req)
{
    DISK_FILTER

    struct val_t val = {};
    u64 ts;

    if (bpf_get_current_comm(&val.name, sizeof(val.name)) == 0) {
        val.pid = bpf_get_current_pid_tgid() >> 32;
        if (##QUEUE##) {
            val.ts = bpf_ktime_get_ns();
        }
        infobyreq.update(&req, &val);
    }
    return 0;
}

// time block I/O
int trace_req_start(struct pt_regs *ctx, struct request *req)
{
    DISK_FILTER

    struct start_req_t start_req = {
        .ts = bpf_ktime_get_ns(),
        .data_len = req->__data_len
    };
    start.update(&req, &start_req);
    return 0;
}

// output
int trace_req_completion(struct pt_regs *ctx, struct request *req)
{
    struct start_req_t *startp;
    struct val_t *valp;
    struct data_t data = {};
    struct gendisk *rq_disk;
    u64 ts;

    // fetch timestamp and calculate delta
    startp = start.lookup(&req);
    if (startp == 0) {
        // missed tracing issue
        return 0;
    }
    ts = bpf_ktime_get_ns();
    rq_disk = req->__RQ_DISK__;
    data.delta = ts - startp->ts;
    data.ts = ts / 1000;
    data.qdelta = 0;
    data.len = startp->data_len;

    valp = infobyreq.lookup(&req);
    if (valp == 0) {
        data.name[0] = '?';
        data.name[1] = 0;
    } else {
        if (##QUEUE##) {
            data.qdelta = startp->ts - valp->ts;
        }
        data.pid = valp->pid;
        data.sector = req->__sector;
        bpf_probe_read_kernel(&data.name, sizeof(data.name), valp->name);
        bpf_probe_read_kernel(&data.disk_name, sizeof(data.disk_name),
                       rq_disk->disk_name);
    }

#ifdef INCLUDE_PATTERN
    data.pattern = UNKNOWN;

    u64 *sector, last_sector;

    struct sector_key_t sector_key = {
        .dev_major = rq_disk->major,
        .dev_minor = rq_disk->first_minor
    };

    sector = last_sectors.lookup(&sector_key);
    if (sector != 0) {
        data.pattern = req->__sector == *sector ? SEQUENTIAL : RANDOM;
    }

    last_sector = req->__sector + data.len / 512;
    last_sectors.update(&sector_key, &last_sector);
#endif

/*
 * The following deals with a kernel version change (in mainline 4.7, although
 * it may be backported to earlier kernels) with how block request write flags
 * are tested. We handle both pre- and post-change versions here. Please avoid
 * kernel version tests like this as much as possible: they inflate the code,
 * test, and maintenance burden.
 */
#ifdef REQ_WRITE
    data.rwflag = !!(req->cmd_flags & REQ_WRITE);
#elif defined(REQ_OP_SHIFT)
    data.rwflag = !!((req->cmd_flags >> REQ_OP_SHIFT) == REQ_OP_WRITE);
#else
    data.rwflag = !!((req->cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);
#endif

    events.perf_submit(ctx, &data, sizeof(data));
    start.delete(&req);
    infobyreq.delete(&req);

    return 0;
}
"""
if args.queue:
    bpf_text = bpf_text.replace('##QUEUE##', '1')
else:
    bpf_text = bpf_text.replace('##QUEUE##', '0')
if BPF.kernel_struct_has_field(b'request', b'rq_disk') == 1:
    bpf_text = bpf_text.replace('__RQ_DISK__', 'rq_disk')
else:
    bpf_text = bpf_text.replace('__RQ_DISK__', 'q->disk')

if args.disk is not None:
    disk_path = os.path.join('/dev', args.disk)
    if not os.path.exists(disk_path):
        print("no such disk '%s'" % args.disk)
        exit(1)

    stat_info = os.stat(disk_path)
    major = os.major(stat_info.st_rdev)
    minor = os.minor(stat_info.st_rdev)

    disk_field_str = ""
    if BPF.kernel_struct_has_field(b'request', b'rq_disk') == 1:
        disk_field_str = 'req->rq_disk'
    else:
        disk_field_str = 'req->q->disk'

    disk_filter_str = """
    struct gendisk *disk = %s;
    if (!(disk->major == %d && disk->first_minor == %d)) {
        return 0;
    }
    """ % (disk_field_str, major, minor)

    bpf_text = bpf_text.replace('DISK_FILTER', disk_filter_str)
else:
    bpf_text = bpf_text.replace('DISK_FILTER', '')

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text)
if BPF.get_kprobe_functions(b'__blk_account_io_start'):
    b.attach_kprobe(event="__blk_account_io_start", fn_name="trace_pid_start")
else:
    b.attach_kprobe(event="blk_account_io_start", fn_name="trace_pid_start")
if BPF.get_kprobe_functions(b'blk_start_request'):
    b.attach_kprobe(event="blk_start_request", fn_name="trace_req_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")
if BPF.get_kprobe_functions(b'__blk_account_io_done'):
    b.attach_kprobe(event="__blk_account_io_done", fn_name="trace_req_completion")
else:
    b.attach_kprobe(event="blk_account_io_done", fn_name="trace_req_completion")

# header
print("%-11s %-14s %-7s %-9s %-1s %-10s %-7s" % ("TIME(s)", "COMM", "PID",
    "DISK", "T", "SECTOR", "BYTES"), end="")
if args.pattern:
    print("%-1s " % ("P"), end="")
if args.queue:
    print("%7s " % ("QUE(ms)"), end="")
print("%7s" % "LAT(ms)")

rwflg = ""
pattern = ""
start_ts = 0
prev_ts = 0
delta = 0

P_SEQUENTIAL = 1
P_RANDOM = 2

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)

    global start_ts
    if start_ts == 0:
        start_ts = event.ts

    if event.rwflag == 1:
        rwflg = "W"
    else:
        rwflg = "R"

    delta = float(event.ts) - start_ts

    disk_name = event.disk_name.decode('utf-8', 'replace')
    if not disk_name:
        disk_name = '<unknown>'

    print("%-11.6f %-14.14s %-7s %-9s %-1s %-10s %-7s" % (
        delta / 1000000, event.name.decode('utf-8', 'replace'), event.pid,
        disk_name, rwflg, event.sector, event.len), end="")
    if args.pattern:
        if event.pattern == P_SEQUENTIAL:
            pattern = "S"
        elif event.pattern == P_RANDOM:
            pattern = "R"
        else:
            pattern = "?"
        print("%-1s " % pattern, end="")
    if args.queue:
        print("%7.2f " % (float(event.qdelta) / 1000000), end="")
    print("%7.2f" % (float(event.delta) / 1000000))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

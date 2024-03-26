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
# 01-Aug-2023   Jerome Marchand Added support for block tracepoints

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
    u32 rwflag;
    sector_t sector;
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
    u32 dev;
    u64 rwflag;
    u64 delta;
    u64 qdelta;
    u64 sector;
    u64 len;
#ifdef INCLUDE_PATTERN
    enum bio_pattern pattern;
#endif
    u64 ts;
    char name[TASK_COMM_LEN];
};

#ifdef INCLUDE_PATTERN
BPF_HASH(last_sectors, struct sector_key_t, u64);
#endif

BPF_HASH(start, struct hash_key, struct start_req_t);
BPF_HASH(infobyreq, struct hash_key, struct val_t);
BPF_PERF_OUTPUT(events);

static dev_t ddevt(struct gendisk *disk) {
    return (disk->major  << 20) | disk->first_minor;
}

/*
 * The following deals with a kernel version change (in mainline 4.7, although
 * it may be backported to earlier kernels) with how block request write flags
 * are tested. We handle both pre- and post-change versions here. Please avoid
 * kernel version tests like this as much as possible: they inflate the code,
 * test, and maintenance burden.
 */
static int get_rwflag(u32 cmd_flags) {
#ifdef REQ_WRITE
    return !!(cmd_flags & REQ_WRITE);
#elif defined(REQ_OP_SHIFT)
    return !!((cmd_flags >> REQ_OP_SHIFT) == REQ_OP_WRITE);
#else
    return !!((cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);
#endif
}

#define RWBS_LEN	8

static int get_rwflag_tp(char *rwbs) {
    for (int i = 0; i < RWBS_LEN; i++) {
        if (rwbs[i] == 'W')
            return 1;
        if (rwbs[i] == '\\0')
            return 0;
    }
    return 0;
}

// cache PID and comm by-req
static int __trace_pid_start(struct hash_key key)
{
    DISK_FILTER

    struct val_t val = {};
    u64 ts;

    if (bpf_get_current_comm(&val.name, sizeof(val.name)) == 0) {
        val.pid = bpf_get_current_pid_tgid() >> 32;
        if (##QUEUE##) {
            val.ts = bpf_ktime_get_ns();
        }
        infobyreq.update(&key, &val);
    }
    return 0;
}


int trace_pid_start(struct pt_regs *ctx, struct request *req)
{
    struct hash_key key = {
        .dev = ddevt(req->__RQ_DISK__),
        .rwflag = get_rwflag(req->cmd_flags),
        .sector = req->__sector
    };

    return __trace_pid_start(key);
}

int trace_pid_start_tp(struct tp_args *args)
{
    struct hash_key key = {
        .dev = args->dev,
        .rwflag = get_rwflag_tp(args->rwbs),
        .sector = args->sector
    };

    return __trace_pid_start(key);
}

// time block I/O
int trace_req_start(struct pt_regs *ctx, struct request *req)
{
    struct hash_key key = {
        .dev = ddevt(req->__RQ_DISK__),
        .rwflag = get_rwflag(req->cmd_flags),
        .sector = req->__sector
    };

    DISK_FILTER

    struct start_req_t start_req = {
        .ts = bpf_ktime_get_ns(),
        .data_len = req->__data_len
    };
    start.update(&key, &start_req);
    return 0;
}

// output
static int __trace_req_completion(void *ctx, struct hash_key key)
{
    struct start_req_t *startp;
    struct val_t *valp;
    struct data_t data = {};
    //struct gendisk *rq_disk;
    u64 ts;

    // fetch timestamp and calculate delta
    startp = start.lookup(&key);
    if (startp == 0) {
        // missed tracing issue
        return 0;
    }
    ts = bpf_ktime_get_ns();
    //rq_disk = req->__RQ_DISK__;
    data.delta = ts - startp->ts;
    data.ts = ts / 1000;
    data.qdelta = 0;
    data.len = startp->data_len;

    valp = infobyreq.lookup(&key);
    if (valp == 0) {
        data.name[0] = '?';
        data.name[1] = 0;
    } else {
        if (##QUEUE##) {
            data.qdelta = startp->ts - valp->ts;
        }
        data.pid = valp->pid;
        data.sector = key.sector;
        data.dev = key.dev;
        bpf_probe_read_kernel(&data.name, sizeof(data.name), valp->name);
    }

#ifdef INCLUDE_PATTERN
    data.pattern = UNKNOWN;

    u64 *sector, last_sector;

    struct sector_key_t sector_key = {
        .dev_major = key.dev >> 20,
        .dev_minor = key.dev & ((1 << 20) - 1)
    };

    sector = last_sectors.lookup(&sector_key);
    if (sector != 0) {
        data.pattern = req->__sector == *sector ? SEQUENTIAL : RANDOM;
    }

    last_sector = req->__sector + data.len / 512;
    last_sectors.update(&sector_key, &last_sector);
#endif

    data.rwflag = key.rwflag;

    events.perf_submit(ctx, &data, sizeof(data));
    start.delete(&key);
    infobyreq.delete(&key);

    return 0;
}

int trace_req_completion(struct pt_regs *ctx, struct request *req)
{
    struct hash_key key = {
        .dev = ddevt(req->__RQ_DISK__),
        .rwflag = get_rwflag(req->cmd_flags),
        .sector = req->__sector
    };

    return __trace_req_completion(ctx, key);
}

int trace_req_completion_tp(struct tp_args *args)
{
    struct hash_key key = {
        .dev = args->dev,
        .rwflag = get_rwflag_tp(args->rwbs),
        .sector = args->sector
    };

    return __trace_req_completion(args, key);
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
    dev = os.major(stat_info.st_rdev) << 20 | os.minor(stat_info.st_rdev)

    disk_filter_str = """
    if(key.dev != %s) {
        return 0;
    }
    """ % (dev)

    bpf_text = bpf_text.replace('DISK_FILTER', disk_filter_str)
else:
    bpf_text = bpf_text.replace('DISK_FILTER', '')

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
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


# header
print("%-11s %-14s %-7s %-9s %-1s %-10s %-7s" % ("TIME(s)", "COMM", "PID",
    "DISK", "T", "SECTOR", "BYTES"), end="")
if args.pattern:
    print("%-1s " % ("P"), end="")
if args.queue:
    print("%7s " % ("QUE(ms)"), end="")
print("%7s" % "LAT(ms)")


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
        diskname = "<unknown>"

    return diskname

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

    disk_name = disk_print(event.dev)

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

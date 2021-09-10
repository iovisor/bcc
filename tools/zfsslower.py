#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# zfsslower  Trace slow ZFS operations.
#            For Linux, uses BCC, eBPF.
#
# USAGE: zfsslower [-h] [-j] [-p PID] [min_ms]
#
# This script traces common ZFS file operations: reads, writes, opens, and
# syncs. It measures the time spent in these operations, and prints details
# for each that exceeded a threshold.
#
# WARNING: This adds low-overhead instrumentation to these ZFS operations,
# including reads and writes from the file system cache. Such reads and writes
# can be very frequent (depending on the workload; eg, 1M/sec), at which
# point the overhead of this tool (even if it prints no "slower" events) can
# begin to become significant.
#
# This works by using kernel dynamic tracing of the ZPL interface, and will
# need updates to match any changes to this interface.
#
# By default, a minimum millisecond threshold of 10 is used.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Feb-2016   Brendan Gregg   Created this.
# 16-Oct-2016   Dina Goldshtein -p to filter by process ID.

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime

# arguments
examples = """examples:
    ./zfsslower             # trace operations slower than 10 ms (default)
    ./zfsslower 1           # trace operations slower than 1 ms
    ./zfsslower -j 1        # ... 1 ms, parsable output (csv)
    ./zfsslower 0           # trace all operations (warning: verbose)
    ./zfsslower -p 185      # trace PID 185 only
"""
parser = argparse.ArgumentParser(
    description="Trace common ZFS file operations slower than a threshold",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-j", "--csv", action="store_true",
    help="just print fields: comma-separated values")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("min_ms", nargs="?", default='10',
    help="minimum I/O duration to trace, in ms (default 10)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
min_ms = int(args.min_ms)
pid = args.pid
csv = args.csv
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/dcache.h>

// XXX: switch these to char's when supported
#define TRACE_READ      0
#define TRACE_WRITE     1
#define TRACE_OPEN      2
#define TRACE_FSYNC     3

struct val_t {
    u64 ts;
    u64 offset;
    struct file *fp;
};

struct data_t {
    // XXX: switch some to u32's when supported
    u64 ts_us;
    u64 type;
    u64 size;
    u64 offset;
    u64 delta_us;
    u64 pid;
    char task[TASK_COMM_LEN];
    char file[DNAME_INLINE_LEN];
};

BPF_HASH(entryinfo, u64, struct val_t);
BPF_PERF_OUTPUT(events);

//
// Store timestamp and size on entry
//

// zpl_read(), zpl_write():
int trace_rw_entry(struct pt_regs *ctx, struct file *filp, char __user *buf,
    size_t len, loff_t *ppos)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part

    if (FILTER_PID)
        return 0;

    // store filep and timestamp by id
    struct val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.fp = filp;
    val.offset = *ppos;
    if (val.fp)
        entryinfo.update(&id, &val);

    return 0;
}

// zpl_open():
int trace_open_entry(struct pt_regs *ctx, struct inode *inode,
    struct file *filp)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part

    if (FILTER_PID)
        return 0;

    // store filep and timestamp by id
    struct val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.fp = filp;
    val.offset = 0;
    if (val.fp)
        entryinfo.update(&id, &val);

    return 0;
}

// zpl_fsync():
int trace_fsync_entry(struct pt_regs *ctx, struct file *filp)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part

    if (FILTER_PID)
        return 0;

    // store filp and timestamp by id
    struct val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.fp = filp;
    val.offset = 0;
    if (val.fp)
        entryinfo.update(&id, &val);

    return 0;
}

//
// Output
//

static int trace_return(struct pt_regs *ctx, int type)
{
    struct val_t *valp;
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part

    valp = entryinfo.lookup(&id);
    if (valp == 0) {
        // missed tracing issue or filtered
        return 0;
    }

    // calculate delta
    u64 ts = bpf_ktime_get_ns();
    u64 delta_us = (ts - valp->ts) / 1000;
    entryinfo.delete(&id);
    if (FILTER_US)
        return 0;

    // populate output struct
    u32 size = PT_REGS_RC(ctx);
    struct data_t data = {.type = type, .size = size, .delta_us = delta_us,
        .pid = pid};
    data.ts_us = ts / 1000;
    data.offset = valp->offset;
    bpf_get_current_comm(&data.task, sizeof(data.task));

    struct qstr qs = valp->fp->f_path.dentry->d_name;
    if (qs.len == 0)
        return 0;
    bpf_probe_read_kernel(&data.file, sizeof(data.file), (void *)qs.name);

    // output
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int trace_read_return(struct pt_regs *ctx)
{
    return trace_return(ctx, TRACE_READ);
}

int trace_write_return(struct pt_regs *ctx)
{
    return trace_return(ctx, TRACE_WRITE);
}

int trace_open_return(struct pt_regs *ctx)
{
    return trace_return(ctx, TRACE_OPEN);
}

int trace_fsync_return(struct pt_regs *ctx)
{
    return trace_return(ctx, TRACE_FSYNC);
}

"""
if min_ms == 0:
    bpf_text = bpf_text.replace('FILTER_US', '0')
else:
    bpf_text = bpf_text.replace('FILTER_US',
        'delta_us <= %s' % str(min_ms * 1000))
if args.pid:
    bpf_text = bpf_text.replace('FILTER_PID', 'pid != %s' % pid)
else:
    bpf_text = bpf_text.replace('FILTER_PID', '0')
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)

    type = 'R'
    if event.type == 1:
        type = 'W'
    elif event.type == 2:
        type = 'O'
    elif event.type == 3:
        type = 'S'

    if (csv):
        print("%d,%s,%d,%s,%d,%d,%d,%s" % (
            event.ts_us, event.task.decode('utf-8', 'replace'), event.pid,
            type, event.size, event.offset, event.delta_us,
            event.file.decode('utf-8', 'replace')))
        return
    print("%-8s %-14.14s %-6s %1s %-7s %-8d %7.2f %s" % (strftime("%H:%M:%S"),
        event.task.decode('utf-8', 'replace'), event.pid, type, event.size,
        event.offset / 1024, float(event.delta_us) / 1000,
        event.file.decode('utf-8', 'replace')))

# initialize BPF
b = BPF(text=bpf_text)

# common file functions
if BPF.get_kprobe_functions(b'zpl_iter'):
    b.attach_kprobe(event="zpl_iter_read", fn_name="trace_rw_entry")
    b.attach_kprobe(event="zpl_iter_write", fn_name="trace_rw_entry")
elif BPF.get_kprobe_functions(b'zpl_aio'):
    b.attach_kprobe(event="zpl_aio_read", fn_name="trace_rw_entry")
    b.attach_kprobe(event="zpl_aio_write", fn_name="trace_rw_entry")
else:
    b.attach_kprobe(event="zpl_read", fn_name="trace_rw_entry")
    b.attach_kprobe(event="zpl_write", fn_name="trace_rw_entry")
b.attach_kprobe(event="zpl_open", fn_name="trace_open_entry")
b.attach_kprobe(event="zpl_fsync", fn_name="trace_fsync_entry")
if BPF.get_kprobe_functions(b'zpl_iter'):
    b.attach_kretprobe(event="zpl_iter_read", fn_name="trace_read_return")
    b.attach_kretprobe(event="zpl_iter_write", fn_name="trace_write_return")
elif BPF.get_kprobe_functions(b'zpl_aio'):
    b.attach_kretprobe(event="zpl_aio_read", fn_name="trace_read_return")
    b.attach_kretprobe(event="zpl_aio_write", fn_name="trace_write_return")
else:
    b.attach_kretprobe(event="zpl_read", fn_name="trace_read_return")
    b.attach_kretprobe(event="zpl_write", fn_name="trace_write_return")
b.attach_kretprobe(event="zpl_open", fn_name="trace_open_return")
b.attach_kretprobe(event="zpl_fsync", fn_name="trace_fsync_return")

# header
if (csv):
    print("ENDTIME_us,TASK,PID,TYPE,BYTES,OFFSET_b,LATENCY_us,FILE")
else:
    if min_ms == 0:
        print("Tracing ZFS operations")
    else:
        print("Tracing ZFS operations slower than %d ms" % min_ms)
    print("%-8s %-14s %-6s %1s %-7s %-8s %7s %s" % ("TIME", "COMM", "PID", "T",
        "BYTES", "OFF_KB", "LAT(ms)", "FILENAME"))

# read events
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

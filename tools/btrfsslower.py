#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# btrfsslower  Trace slow btrfs operations.
#              For Linux, uses BCC, eBPF.
#
# USAGE: btrfsslower [-h] [-j] [-p PID] [min_ms]
#
# This script traces common btrfs file operations: reads, writes, opens, and
# syncs. It measures the time spent in these operations, and prints details
# for each that exceeded a threshold.
#
# WARNING: This adds low-overhead instrumentation to these btrfs operations,
# including reads and writes from the file system cache. Such reads and writes
# can be very frequent (depending on the workload; eg, 1M/sec), at which
# point the overhead of this tool (even if it prints no "slower" events) can
# begin to become significant.
#
# By default, a minimum millisecond threshold of 10 is used.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 15-Feb-2016   Brendan Gregg   Created this.
# 16-Oct-2016   Dina Goldshtein -p to filter by process ID.

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime
import ctypes as ct

# symbols
kallsyms = "/proc/kallsyms"

# arguments
examples = """examples:
    ./btrfsslower             # trace operations slower than 10 ms (default)
    ./btrfsslower 1           # trace operations slower than 1 ms
    ./btrfsslower -j 1        # ... 1 ms, parsable output (csv)
    ./btrfsslower 0           # trace all operations (warning: verbose)
    ./btrfsslower -p 185      # trace PID 185 only
"""
parser = argparse.ArgumentParser(
    description="Trace common btrfs file operations slower than a threshold",
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

// The current btrfs (Linux 4.5) uses generic_file_read_iter() instead of it's
// own read function. So we need to trace that and then filter on btrfs, which
// I do by checking file->f_op.
int trace_read_entry(struct pt_regs *ctx, struct kiocb *iocb)
{
    u64 id =  bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part

    if (FILTER_PID)
        return 0;

    // btrfs filter on file->f_op == btrfs_file_operations
    struct file *fp = iocb->ki_filp;
    if ((u64)fp->f_op != BTRFS_FILE_OPERATIONS)
        return 0;

    // store filep and timestamp by pid
    struct val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.fp = fp;
    val.offset = iocb->ki_pos;
    if (val.fp)
        entryinfo.update(&id, &val);

    return 0;
}

// btrfs_file_write_iter():
int trace_write_entry(struct pt_regs *ctx, struct kiocb *iocb)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part

    if (FILTER_PID)
        return 0;

    // store filep and timestamp by id
    struct val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.fp = iocb->ki_filp;
    val.offset = iocb->ki_pos;
    if (val.fp)
        entryinfo.update(&id, &val);

    return 0;
}

// The current btrfs (Linux 4.5) uses generic_file_open(), instead of it's own
// function. Same as with reads. Trace the generic path and filter:
int trace_open_entry(struct pt_regs *ctx, struct inode *inode,
    struct file *file)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part

    if (FILTER_PID)
        return 0;

    // btrfs filter on file->f_op == btrfs_file_operations
    if ((u64)file->f_op != BTRFS_FILE_OPERATIONS)
        return 0;

    // store filep and timestamp by id
    struct val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.fp = file;
    val.offset = 0;
    if (val.fp)
        entryinfo.update(&id, &val);

    return 0;
}

// btrfs_sync_file():
int trace_fsync_entry(struct pt_regs *ctx, struct file *file)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part

    if (FILTER_PID)
        return 0;

    // store filep and timestamp by id
    struct val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.fp = file;
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

    // workaround (rewriter should handle file to d_name in one step):
    struct dentry *de = NULL;
    struct qstr qs = {};
    de = valp->fp->f_path.dentry;
    qs = de->d_name;
    if (qs.len == 0)
        return 0;
    bpf_probe_read(&data.file, sizeof(data.file), (void *)qs.name);

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

# code replacements
with open(kallsyms) as syms:
    ops = ''
    for line in syms:
        a = line.rstrip().split()
        (addr, name) = (a[0], a[2])
        name = name.split("\t")[0]
        if name == "btrfs_file_operations":
            ops = "0x" + addr
            break
    if ops == '':
        print("ERROR: no btrfs_file_operations in /proc/kallsyms. Exiting.")
        print("HINT: the kernel should be built with CONFIG_KALLSYMS_ALL.")
        exit()
    bpf_text = bpf_text.replace('BTRFS_FILE_OPERATIONS', ops)
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

# kernel->user event data: struct data_t
DNAME_INLINE_LEN = 32   # linux/dcache.h
TASK_COMM_LEN = 16      # linux/sched.h
class Data(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("type", ct.c_ulonglong),
        ("size", ct.c_ulonglong),
        ("offset", ct.c_ulonglong),
        ("delta_us", ct.c_ulonglong),
        ("pid", ct.c_ulonglong),
        ("task", ct.c_char * TASK_COMM_LEN),
        ("file", ct.c_char * DNAME_INLINE_LEN)
    ]

# process event
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents

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

# Common file functions. See earlier comment about generic_*().
b.attach_kprobe(event="generic_file_read_iter", fn_name="trace_read_entry")
b.attach_kprobe(event="btrfs_file_write_iter", fn_name="trace_write_entry")
b.attach_kprobe(event="generic_file_open", fn_name="trace_open_entry")
b.attach_kprobe(event="btrfs_sync_file", fn_name="trace_fsync_entry")
b.attach_kretprobe(event="generic_file_read_iter", fn_name="trace_read_return")
b.attach_kretprobe(event="btrfs_file_write_iter", fn_name="trace_write_return")
b.attach_kretprobe(event="generic_file_open", fn_name="trace_open_return")
b.attach_kretprobe(event="btrfs_sync_file", fn_name="trace_fsync_return")

# header
if (csv):
    print("ENDTIME_us,TASK,PID,TYPE,BYTES,OFFSET_b,LATENCY_us,FILE")
else:
    if min_ms == 0:
        print("Tracing btrfs operations")
    else:
        print("Tracing btrfs operations slower than %d ms" % min_ms)
    print("%-8s %-14s %-6s %1s %-7s %-8s %7s %s" % ("TIME", "COMM", "PID", "T",
        "BYTES", "OFF_KB", "LAT(ms)", "FILENAME"))

# read events
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    b.perf_buffer_poll()

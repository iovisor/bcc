#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# fileslower  Trace slow synchronous file reads and writes.
#             For Linux, uses BCC, eBPF.
#
# USAGE: fileslower [-h] [-p PID] [min_ms]
#
# This script uses kernel dynamic tracing of synchronous reads and writes
# at the VFS interface, to identify slow file reads and writes for any file
# system.
#
# This works by tracing __vfs_read() and __vfs_write(), and filtering for
# synchronous I/O (the path to new_sync_read() and new_sync_write()), and
# for I/O with filenames. This approach provides a view of just two file
# system request types. There are typically many others: asynchronous I/O,
# directory operations, file handle operations, etc, that this tool does not
# instrument.
#
# WARNING: This traces VFS reads and writes, which can be extremely frequent,
# and so the overhead of this tool can become severe depending on the
# workload.
#
# By default, a minimum millisecond threshold of 10 is used.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 06-Feb-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
import argparse
import signal

# arguments
examples = """examples:
    ./fileslower             # trace sync file I/O slower than 10 ms (default)
    ./fileslower 1           # trace sync file I/O slower than 1 ms
    ./fileslower -p 185      # trace PID 185 only
"""
parser = argparse.ArgumentParser(
    description="Trace slow synchronous file reads and writes",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("min_ms", nargs="?", default='10',
    help="minimum I/O duration to trace, in ms (default 10)")
args = parser.parse_args()
min_ms = int(args.min_ms)
pid = args.pid
debug = 0

# signal handler
def signal_ignore(signal, frame):
    print()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>

#define TRACE_READ	0
#define TRACE_WRITE	1

struct val_t {
    u32 sz;
    u64 ts;
    char name[DNAME_INLINE_LEN];
};

BPF_HASH(entryinfo, pid_t, struct val_t);

// store timestamp and size on entry
static int trace_rw_entry(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count)
{
    u32 pid;

    pid = bpf_get_current_pid_tgid();
    if (FILTER)
        return 0;

    // skip I/O lacking a filename
    struct dentry *de = file->f_path.dentry;
    if (de->d_iname[0] == 0)
        return 0;

    // store size and timestamp by pid
    struct val_t val = {};
    val.sz = count;
    val.ts = bpf_ktime_get_ns();
    __builtin_memcpy(&val.name, de->d_iname, sizeof(val.name));
    entryinfo.update(&pid, &val);

    return 0;
}

int trace_read_entry(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count)
{
    // skip non-sync I/O; see kernel code for __vfs_read()
    if (!(file->f_op->read_iter))
        return 0;
    return trace_rw_entry(ctx, file, buf, count);
}

int trace_write_entry(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count)
{
    // skip non-sync I/O; see kernel code for __vfs_write()
    if (!(file->f_op->write_iter))
        return 0;
    return trace_rw_entry(ctx, file, buf, count);
}

// output
static int trace_rw_return(struct pt_regs *ctx, int type)
{
    struct val_t *valp;
    u32 pid = bpf_get_current_pid_tgid();

    valp = entryinfo.lookup(&pid);
    if (valp == 0) {
        // missed tracing issue or filtered
        return 0;
    }
    u64 delta_us = (bpf_ktime_get_ns() - valp->ts) / 1000;
    entryinfo.delete(&pid);
    if (delta_us < MIN_US)
        return 0;

    if (type == TRACE_READ) {
        bpf_trace_printk("R %d %d %s\\n", valp->sz, delta_us, valp->name);
    } else {
        bpf_trace_printk("W %d %d %s\\n", valp->sz, delta_us, valp->name);
    }

    return 0;
}

int trace_read_return(struct pt_regs *ctx)
{
    return trace_rw_return(ctx, TRACE_READ);
}

int trace_write_return(struct pt_regs *ctx)
{
    return trace_rw_return(ctx, TRACE_WRITE);
}

"""
bpf_text = bpf_text.replace('MIN_US', str(min_ms * 1000))
if args.pid:
    bpf_text = bpf_text.replace('FILTER', 'pid != %s' % pid)
else:
    bpf_text = bpf_text.replace('FILTER', '0')
if debug:
    print(bpf_text)

# initialize BPF
b = BPF(text=bpf_text)

# I'd rather trace these via new_sync_read/new_sync_write (which used to be
# do_sync_read/do_sync_write), but those became static. So trace these from
# the parent functions, at the cost of more overhead, instead.
# Ultimately, we should be using [V]FS tracepoints.
b.attach_kprobe(event="__vfs_read", fn_name="trace_read_entry")
b.attach_kprobe(event="__vfs_write", fn_name="trace_write_entry")
b.attach_kretprobe(event="__vfs_read", fn_name="trace_read_return")
b.attach_kretprobe(event="__vfs_write", fn_name="trace_write_return")

# header
print("Tracing sync read/writes slower than %d ms" % min_ms)
print("%-8s %-14s %-6s %1s %-7s %7s %s" % ("TIME(s)", "COMM", "PID", "D",
    "BYTES", "LAT(ms)", "FILENAME"))

start_ts = 0

# format output
while 1:
    (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    args = msg.split(" ", 3)
    (type_s, sz, delta_us_s) = (args[0], args[1], args[2])
    try:
        filename = args[3]
    except:
        filename = "?"
    if start_ts == 0:
        start_ts = ts

    ms = float(int(delta_us_s, 10)) / 1000

    print("%-8.3f %-14.14s %-6s %1s %-7s %7.2f %s" % (
        ts - start_ts, task, pid, type_s, sz, ms, filename))

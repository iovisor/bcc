#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# fileslower  Trace slow synchronous file reads and writes.
#             For Linux, uses BCC, eBPF.
#
# USAGE: fileslower [-h] [-p PID] [-a] [min_ms]
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
import ctypes as ct
import time

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
parser.add_argument("-p", "--pid", type=int, metavar="PID", dest="tgid",
    help="trace this PID only")
parser.add_argument("-a", "--all-files", action="store_true",
    help="include non-regular file types (sockets, FIFOs, etc)")
parser.add_argument("min_ms", nargs="?", default='10',
    help="minimum I/O duration to trace, in ms (default 10)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
min_ms = int(args.min_ms)
tgid = args.tgid
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

enum trace_mode {
    MODE_READ,
    MODE_WRITE
};

struct val_t {
    u32 sz;
    u64 ts;
    u32 name_len;
    // de->d_name.name may point to de->d_iname so limit len accordingly
    char name[DNAME_INLINE_LEN];
    char comm[TASK_COMM_LEN];
};

struct data_t {
    enum trace_mode mode;
    u32 pid;
    u32 sz;
    u64 delta_us;
    u32 name_len;
    char name[DNAME_INLINE_LEN];
    char comm[TASK_COMM_LEN];
};

BPF_HASH(entryinfo, pid_t, struct val_t);
BPF_PERF_OUTPUT(events);

// store timestamp and size on entry
static int trace_rw_entry(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    if (TGID_FILTER)
        return 0;

    u32 pid = bpf_get_current_pid_tgid();

    // skip I/O lacking a filename
    struct dentry *de = file->f_path.dentry;
    int mode = file->f_inode->i_mode;
    if (de->d_name.len == 0 || TYPE_FILTER)
        return 0;

    // store size and timestamp by pid
    struct val_t val = {};
    val.sz = count;
    val.ts = bpf_ktime_get_ns();

    struct qstr d_name = de->d_name;
    val.name_len = d_name.len;
    bpf_probe_read(&val.name, sizeof(val.name), d_name.name);
    bpf_get_current_comm(&val.comm, sizeof(val.comm));
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

    struct data_t data = {};
    data.mode = type;
    data.pid = pid;
    data.sz = valp->sz;
    data.delta_us = delta_us;
    data.name_len = valp->name_len;
    bpf_probe_read(&data.name, sizeof(data.name), valp->name);
    bpf_probe_read(&data.comm, sizeof(data.comm), valp->comm);
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int trace_read_return(struct pt_regs *ctx)
{
    return trace_rw_return(ctx, MODE_READ);
}

int trace_write_return(struct pt_regs *ctx)
{
    return trace_rw_return(ctx, MODE_WRITE);
}

"""
bpf_text = bpf_text.replace('MIN_US', str(min_ms * 1000))
if args.tgid:
    bpf_text = bpf_text.replace('TGID_FILTER', 'tgid != %d' % tgid)
else:
    bpf_text = bpf_text.replace('TGID_FILTER', '0')
if args.all_files:
    bpf_text = bpf_text.replace('TYPE_FILTER', '0')
else:
    bpf_text = bpf_text.replace('TYPE_FILTER', '!S_ISREG(mode)')

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text)

# I'd rather trace these via new_sync_read/new_sync_write (which used to be
# do_sync_read/do_sync_write), but those became static. So trace these from
# the parent functions, at the cost of more overhead, instead.
# Ultimately, we should be using [V]FS tracepoints.
b.attach_kprobe(event="__vfs_read", fn_name="trace_read_entry")
b.attach_kretprobe(event="__vfs_read", fn_name="trace_read_return")
try:
    b.attach_kprobe(event="__vfs_write", fn_name="trace_write_entry")
    b.attach_kretprobe(event="__vfs_write", fn_name="trace_write_return")
except:
    # older kernels don't have __vfs_write so try vfs_write instead
    b.attach_kprobe(event="vfs_write", fn_name="trace_write_entry")
    b.attach_kretprobe(event="vfs_write", fn_name="trace_write_return")

TASK_COMM_LEN = 16  # linux/sched.h
DNAME_INLINE_LEN = 32  # linux/dcache.h

class Data(ct.Structure):
    _fields_ = [
        ("mode", ct.c_int),
        ("pid", ct.c_uint),
        ("sz", ct.c_uint),
        ("delta_us", ct.c_ulonglong),
        ("name_len", ct.c_uint),
        ("name", ct.c_char * DNAME_INLINE_LEN),
        ("comm", ct.c_char * TASK_COMM_LEN),
    ]

mode_s = {
    0: 'R',
    1: 'W',
}

# header
print("Tracing sync read/writes slower than %d ms" % min_ms)
print("%-8s %-14s %-6s %1s %-7s %7s %s" % ("TIME(s)", "COMM", "TID", "D",
    "BYTES", "LAT(ms)", "FILENAME"))

start_ts = time.time()

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents

    ms = float(event.delta_us) / 1000
    name = event.name.decode('utf-8', 'replace')
    if event.name_len > DNAME_INLINE_LEN:
        name = name[:-3] + "..."

    print("%-8.3f %-14.14s %-6s %1s %-7s %7.2f %s" % (
        time.time() - start_ts, event.comm.decode('utf-8', 'replace'),
        event.pid, mode_s[event.mode], event.sz, ms, name))

b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    b.perf_buffer_poll()

#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# nfsslower     Trace slow NFS operations
#               for Linux using BCC & eBPF
#
# Usage: nfsslower [-h] [-p PID] [min_ms]
#
# This script traces some common NFS operations: read, write, opens and
# getattr. It measures the time spent in these operations, and prints details
# for each that exceeded a threshold.
#
# WARNING: This adds low-overhead instrumentation to these NFS operations,
# including reads and writes from the file system cache. Such reads and writes
# can be very frequent (depending on the workload; eg, 1M/sec), at which
# point the overhead of this tool (even if it prints no "slower" events) can
# begin to become significant.
#
# Most of this code is copied from similar tools (ext4slower, zfsslower etc)
#
# By default, a minimum millisecond threshold of 10 is used.
#
# This tool uses kprobes to instrument the kernel for entry and exit
# information, in the future a preferred way would be to use tracepoints.
# Currently there are'nt any tracepoints available for nfs_read_file,
# nfs_write_file and nfs_open_file, nfs_getattr does have entry and exit
# tracepoints but we chose to use kprobes for consistency
#
# 31-Aug-2017   Samuel Nair created this. Should work with NFSv{3,4}

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime
import ctypes as ct

examples = """
    ./nfsslower         # trace operations slower than 10ms
    ./nfsslower 1       # trace operations slower than 1ms
    ./nfsslower -j 1    # ... 1 ms, parsable output (csv)
    ./nfsslower 0       # trace all nfs operations
    ./nfsslower -p 121  # trace pid 121 only
"""
parser = argparse.ArgumentParser(
    description="""Trace READ, WRITE, OPEN \
and GETATTR NFS calls slower than a threshold,\
supports NFSv{3,4}""",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

parser.add_argument("-j", "--csv", action="store_true",
                    help="just print fields: comma-separated values")
parser.add_argument("-p", "--pid", help="Trace this pid only")
parser.add_argument("min_ms", nargs="?", default='10',
                    help="Minimum IO duration to trace in ms (default=10ms)")
parser.add_argument("--ebpf", action="store_true",
                    help=argparse.SUPPRESS)
args = parser.parse_args()
min_ms = int(args.min_ms)
pid = args.pid
csv = args.csv
debug = 0

bpf_text = """

#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/dcache.h>

#define TRACE_READ 0
#define TRACE_WRITE 1
#define TRACE_OPEN 2
#define TRACE_GETATTR 3

struct val_t {
    u64 ts;
    u64 offset;
    struct file *fp;
    struct dentry *d;
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

int trace_rw_entry(struct pt_regs *ctx, struct kiocb *iocb,
                                struct iov_iter *data)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part

    if(FILTER_PID)
        return 0;

    // store filep and timestamp by id
    struct val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.fp = iocb->ki_filp;
    val.d = NULL;
    val.offset = iocb->ki_pos;

    if (val.fp)
        entryinfo.update(&id, &val);

    return 0;
}

int trace_file_open_entry (struct pt_regs *ctx, struct inode *inode,
                                struct file *filp)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part

    if(FILTER_PID)
        return 0;

    // store filep and timestamp by id
    struct val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.fp = filp;
    val.d = NULL;
    val.offset = 0;
    if (val.fp)
        entryinfo.update(&id, &val);

    return 0;
}

int trace_getattr_entry(struct pt_regs *ctx, struct vfsmount *mnt,
                        struct dentry *dentry, struct kstat *stat)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part

    if(FILTER_PID)
        return 0;

    struct val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.fp = NULL;
    val.d = dentry;
    val.offset = 0;
    if (val.d)
        entryinfo.update(&id, &val);

    return 0;
}

static int trace_exit(struct pt_regs *ctx, int type)
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
    if(type == TRACE_GETATTR)
    {
        bpf_probe_read(&de,sizeof(de), &valp->d);
    }
    else
    {
        bpf_probe_read(&de, sizeof(de), &valp->fp->f_path.dentry);
    }

    bpf_probe_read(&qs, sizeof(qs), (void *)&de->d_name);
    if (qs.len == 0)
        return 0;

    bpf_probe_read(&data.file, sizeof(data.file), (void *)qs.name);
    // output
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_file_open_return(struct pt_regs *ctx)
{
    return trace_exit(ctx, TRACE_OPEN);
}

int trace_read_return(struct pt_regs *ctx)
{
    return trace_exit(ctx, TRACE_READ);
}

int trace_write_return(struct pt_regs *ctx)
{
    return trace_exit(ctx, TRACE_WRITE);
}

int trace_getattr_return(struct pt_regs *ctx)
{
    return trace_exit(ctx, TRACE_GETATTR);
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
        type = 'G'

    if(csv):
        print("%d,%s,%d,%s,%d,%d,%d,%s" % (
            event.ts_us, event.task, event.pid, type, event.size,
            event.offset, event.delta_us, event.file))
        return
    print("%-8s %-14.14s %-6s %1s %-7s %-8d %7.2f %s" %
          (strftime("%H:%M:%S"),
           event.task.decode('utf-8', 'replace'),
           event.pid,
           type,
           event.size,
           event.offset / 1024,
           float(event.delta_us) / 1000,
           event.file.decode('utf-8', 'replace')))


# Currently specifically works for NFSv4, the other kprobes are generic
# so it should work with earlier NFS versions

b = BPF(text=bpf_text)
b.attach_kprobe(event="nfs_file_read", fn_name="trace_rw_entry")
b.attach_kprobe(event="nfs_file_write", fn_name="trace_rw_entry")
b.attach_kprobe(event="nfs4_file_open", fn_name="trace_file_open_entry")
b.attach_kprobe(event="nfs_file_open", fn_name="trace_file_open_entry")
b.attach_kprobe(event="nfs_getattr", fn_name="trace_getattr_entry")

b.attach_kretprobe(event="nfs_file_read", fn_name="trace_read_return")
b.attach_kretprobe(event="nfs_file_write", fn_name="trace_write_return")
b.attach_kretprobe(event="nfs4_file_open", fn_name="trace_file_open_return")
b.attach_kretprobe(event="nfs_file_open", fn_name="trace_file_open_return")
b.attach_kretprobe(event="nfs_getattr", fn_name="trace_getattr_return")

if(csv):
    print("ENDTIME_us,TASK,PID,TYPE,BYTES,OFFSET_b,LATENCY_us,FILE")
else:
    if min_ms == 0:
        print("Tracing NFS operations... Ctrl-C to quit")
    else:
        print("""Tracing NFS operations that are slower than \
%d ms... Ctrl-C to quit"""
              % min_ms)
    print("%-8s %-14s %-6s %1s %-7s %-8s %7s %s" % ("TIME",
                                                    "COMM",
                                                    "PID",
                                                    "T",
                                                    "BYTES",
                                                    "OFF_KB",
                                                    "LAT(ms)",
                                                    "FILENAME"))

b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
        b.perf_buffer_poll()

#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# filelife    Trace the lifespan of short-lived files.
#             For Linux, uses BCC, eBPF. Embedded C.
#
# This traces the creation and deletion of files, providing information
# on who deleted the file, the file age, and the file name. The intent is to
# provide information on short-lived files, for debugging or performance
# analysis.
#
# USAGE: filelife [-h] [-p PID]
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 08-Feb-2015   Brendan Gregg   Created this.
# 17-Feb-2016   Allan McAleavy updated for BPF_PERF_OUTPUT
# 13-Nov-2022   Rong Tao        Check btf struct field for CO-RE and add vfs_open()

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime

# arguments
examples = """examples:
    ./filelife           # trace lifecycle of file(create->remove)
    ./filelife -p 181    # only trace PID 181
"""
parser = argparse.ArgumentParser(
    description="Trace lifecycle of file",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u64 delta;
    char comm[TASK_COMM_LEN];
    char fname[DNAME_INLINE_LEN];
};

BPF_HASH(birth, struct dentry *);
BPF_PERF_OUTPUT(events);

static int probe_dentry(struct pt_regs *ctx, struct dentry *dentry)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER

    u64 ts = bpf_ktime_get_ns();
    birth.update(&dentry, &ts);

    return 0;
}

// trace file creation time
TRACE_CREATE_FUNC
{
    return probe_dentry(ctx, dentry);
};

// trace file security_inode_create time
int trace_security_inode_create(struct pt_regs *ctx, struct inode *dir,
        struct dentry *dentry)
{
    return probe_dentry(ctx, dentry);
};

// trace file open time
int trace_open(struct pt_regs *ctx, struct path *path, struct file *file)
{
    struct dentry *dentry = path->dentry;

    if (!(file->f_mode & FMODE_CREATED)) {
        return 0;
    }

    return probe_dentry(ctx, dentry);
};

// trace file deletion and output details
TRACE_UNLINK_FUNC
{
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    FILTER

    u64 *tsp, delta;
    tsp = birth.lookup(&dentry);
    if (tsp == 0) {
        return 0;   // missed create
    }

    delta = (bpf_ktime_get_ns() - *tsp) / 1000000;
    birth.delete(&dentry);

    struct qstr d_name = dentry->d_name;
    if (d_name.len == 0)
        return 0;

    if (bpf_get_current_comm(&data.comm, sizeof(data.comm)) == 0) {
        data.pid = pid;
        data.delta = delta;
        bpf_probe_read_kernel(&data.fname, sizeof(data.fname), d_name.name);
    }

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

trace_create_text_old="""
int trace_create(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
"""
trace_create_text_new="""
int trace_create(struct pt_regs *ctx, struct user_namespace *mnt_userns,
        struct inode *dir, struct dentry *dentry)
"""

trace_unlink_text_old="""
int trace_unlink(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
"""
trace_unlink_text_new="""
int trace_unlink(struct pt_regs *ctx, struct user_namespace *mnt_userns,
        struct inode *dir, struct dentry *dentry)
"""

if args.pid:
    bpf_text = bpf_text.replace('FILTER',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '')
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

if BPF.kernel_struct_has_field(b'renamedata', b'old_mnt_userns') == 1:
    bpf_text = bpf_text.replace('TRACE_CREATE_FUNC', trace_create_text_new)
    bpf_text = bpf_text.replace('TRACE_UNLINK_FUNC', trace_unlink_text_new)
else:
    bpf_text = bpf_text.replace('TRACE_CREATE_FUNC', trace_create_text_old)
    bpf_text = bpf_text.replace('TRACE_UNLINK_FUNC', trace_unlink_text_old)

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="vfs_create", fn_name="trace_create")
# newer kernels may don't fire vfs_create, call vfs_open instead:
b.attach_kprobe(event="vfs_open", fn_name="trace_open")
# newer kernels (say, 4.8) may don't fire vfs_create, so record (or overwrite)
# the timestamp in security_inode_create():
if BPF.get_kprobe_functions(b"security_inode_create"):
    b.attach_kprobe(event="security_inode_create", fn_name="trace_security_inode_create")
b.attach_kprobe(event="vfs_unlink", fn_name="trace_unlink")

# header
print("%-8s %-7s %-16s %-7s %s" % ("TIME", "PID", "COMM", "AGE(s)", "FILE"))

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%-8s %-7d %-16s %-7.2f %s" % (strftime("%H:%M:%S"), event.pid,
        event.comm.decode('utf-8', 'replace'), float(event.delta) / 1000,
        event.fname.decode('utf-8', 'replace')))

b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

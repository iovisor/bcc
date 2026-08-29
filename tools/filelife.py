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
# 05-Nov-2023   Rong Tao        Support unlink failed
# 01-Jul-2025   Rong Tao        Support file path

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
import argparse
from time import strftime

# arguments
examples = """examples:
    ./filelife           # trace lifecycle of file(create->remove)
    ./filelife -P        # show path of file
    ./filelife -p 181    # only trace PID 181
"""
parser = argparse.ArgumentParser(
    description="Trace lifecycle of file",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-P", "--path", action="store_true",
    help="show file path")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/fs_struct.h>
#ifdef FULLPATH
INCLUDE_FULL_PATH_H
INCLUDE_PATH_HELPERS_BPF_H
#endif

struct data_t {
    u32 pid;
    u64 delta;
    char comm[TASK_COMM_LEN];
    u32 path_depth;
#ifdef FULLPATH
    FULL_PATH_FIELD(fname);
#else
    char fname[DNAME_INLINE_LEN];
#endif
};

struct create_arg {
    u64 ts;
    struct vfsmount *cwd_vfsmnt;
};

struct unlink_event {
    u32 tid;
    u64 delta;
    struct dentry *dentry;
    struct vfsmount *cwd_vfsmnt;
};

BPF_HASH(birth, struct dentry *, struct create_arg);
BPF_HASH(unlink_data, u32, struct unlink_event);
BPF_RINGBUF_OUTPUT(events, 64);

static int probe_dentry(struct pt_regs *ctx, struct dentry *dentry)
{
    struct task_struct *task;
    struct fs_struct *fs;
    struct create_arg arg = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER

    u64 ts = bpf_ktime_get_ns();

    arg.ts = ts;
    task = (struct task_struct *)bpf_get_current_task_btf();

    arg.ts = ts;
    bpf_probe_read_kernel(&fs, sizeof(fs), &task->fs);
    bpf_probe_read_kernel(&arg.cwd_vfsmnt, sizeof(arg.cwd_vfsmnt), &fs->pwd.mnt);

    birth.update(&dentry, &arg);

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
    struct create_arg *arg;
    struct unlink_event event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    FILTER

    u64 delta;
    arg = birth.lookup(&dentry);
    if (arg == 0) {
        return 0;   // missed create
    }

    delta = (bpf_ktime_get_ns() - arg->ts) / 1000000;

    /* record dentry, only delete from birth if unlink successful */
    event.delta = delta;
    event.tid = tid;
    event.dentry = dentry;
    event.cwd_vfsmnt = arg->cwd_vfsmnt;

    unlink_data.update(&tid, &event);
    return 0;
}

int trace_unlink_ret(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    struct unlink_event *unlink_event;
    struct data_t *data;
    u32 tid = (u32)bpf_get_current_pid_tgid();

    unlink_event = unlink_data.lookup(&tid);
    if (!unlink_event)
        return 0;

    /* delete it any way */
    unlink_data.delete(&tid);

    /* Skip failed unlink */
    if (ret)
        return 0;

    data = events.ringbuf_reserve(sizeof(struct data_t));
    if (!data)
        return 0;

    data->pid = unlink_event->tid;
    data->delta = unlink_event->delta;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    data->path_depth = 0;

#ifdef FULLPATH
    if (data->fname[0] != '/') {
        bpf_dentry_full_path(data->fname, NAME_MAX, MAX_ENTRIES,
                             unlink_event->dentry, unlink_event->cwd_vfsmnt,
                             &data->path_depth);
    }
#else
    struct qstr d_name = unlink_event->dentry->d_name;
    bpf_probe_read_kernel_str(&data->fname, sizeof(data->fname), d_name.name);
#endif

    birth.delete((struct dentry **)&unlink_event->dentry);

    events.ringbuf_submit(data, sizeof(*data));

    return 0;
}
"""

trace_create_text_1="""
int trace_create(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
"""
trace_create_text_2="""
int trace_create(struct pt_regs *ctx, struct user_namespace *mnt_userns,
        struct inode *dir, struct dentry *dentry)
"""
trace_create_text_3="""
int trace_create(struct pt_regs *ctx, struct mnt_idmap *idmap,
        struct inode *dir, struct dentry *dentry)
"""

trace_unlink_text_1="""
int trace_unlink(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
"""
trace_unlink_text_2="""
int trace_unlink(struct pt_regs *ctx, struct user_namespace *mnt_userns,
        struct inode *dir, struct dentry *dentry)
"""
trace_unlink_text_3="""
int trace_unlink(struct pt_regs *ctx, struct mnt_idmap *idmap,
        struct inode *dir, struct dentry *dentry)
"""

if args.pid:
    bpf_text = bpf_text.replace('FILTER',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '')

if args.path:
    bpf_text = "#define FULLPATH\n" + bpf_text

    with open(BPF._find_file("full_path.h".encode("utf-8"))) as fileobj:
        progtxt = fileobj.read()
    bpf_text = bpf_text.replace('INCLUDE_FULL_PATH_H', progtxt)

    with open(BPF._find_file("path_helpers.bpf.c".encode("utf-8"))) as fileobj:
        progtxt = fileobj.read()
    bpf_text = bpf_text.replace('INCLUDE_PATH_HELPERS_BPF_H', progtxt)

if BPF.kernel_struct_has_field(b'renamedata', b'new_mnt_idmap') == 1:
    bpf_text = bpf_text.replace('TRACE_CREATE_FUNC', trace_create_text_3)
    bpf_text = bpf_text.replace('TRACE_UNLINK_FUNC', trace_unlink_text_3)
elif BPF.kernel_struct_has_field(b'renamedata', b'old_mnt_userns') == 1:
    bpf_text = bpf_text.replace('TRACE_CREATE_FUNC', trace_create_text_2)
    bpf_text = bpf_text.replace('TRACE_UNLINK_FUNC', trace_unlink_text_2)
else:
    bpf_text = bpf_text.replace('TRACE_CREATE_FUNC', trace_create_text_1)
    bpf_text = bpf_text.replace('TRACE_UNLINK_FUNC', trace_unlink_text_1)

# NOTE: After bpf_text modification
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

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
b.attach_kretprobe(event="vfs_unlink", fn_name="trace_unlink_ret")

# header
print("%-8s %-7s %-16s %-7s %s" % ("TIME", "PID", "COMM", "AGE(s)", "FILE"))

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    printb(b"%-8s %-7d %-16s %-7.2f " % (strftime("%H:%M:%S").encode('utf-8', 'replace'),
           event.pid, event.comm, float(event.delta) / 1000), nl="")
    if args.path:
        import os
        import sys
        sys.path.append(os.path.dirname(sys.argv[0]))
        from path_helpers import get_full_path
        result = get_full_path(event.fname, event.path_depth)
        printb(b"%s" % result.encode("utf-8"))
    else:
        printb(b"%s" % event.fname)

b["events"].open_ring_buffer(print_event)
while 1:
    try:
        b.ring_buffer_poll()
    except KeyboardInterrupt:
        exit()

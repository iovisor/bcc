#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# filegone    Trace why file gone (deleted or renamed).
#             For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: filegone [-h] [-p PID]
#
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 08-Nov-2022 Curu. modified from filelife
# 19-Nov-2022 Rong Tao Check btf struct field instead of KERNEL_VERSION macro.

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime

# arguments
examples = """examples:
    ./filegone           # trace all file gone events
    ./filegone -p 181    # only trace PID 181
"""
parser = argparse.ArgumentParser(
    description="Trace why file gone (deleted or renamed)",
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
    u8 action;
    char comm[TASK_COMM_LEN];
    char fname[DNAME_INLINE_LEN];
    char fname2[DNAME_INLINE_LEN];
};

BPF_PERF_OUTPUT(events);

// trace file deletion and output details
TRACE_VFS_UNLINK_FUNC
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    FILTER

    struct data_t data = {};
    struct qstr d_name = dentry->d_name;
    if (d_name.len == 0)
        return 0;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.pid = pid;
    data.action = 'D';
    bpf_probe_read(&data.fname, sizeof(data.fname), d_name.name);

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

// trace file rename
TRACE_VFS_RENAME_FUNC

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    FILTER

    struct data_t data = {};
    struct qstr s_name = old_dentry->d_name;
    struct qstr d_name = new_dentry->d_name;
    if (s_name.len == 0 || d_name.len == 0)
        return 0;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.pid = pid;
    data.action = 'R';
    bpf_probe_read(&data.fname, sizeof(data.fname), s_name.name);
    bpf_probe_read(&data.fname2, sizeof(data.fname), d_name.name);
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

bpf_vfs_rename_text_old="""
int trace_rename(struct pt_regs *ctx, struct inode *old_dir, struct dentry *old_dentry,
struct inode *new_dir, struct dentry *new_dentry)
{
"""
bpf_vfs_rename_text_new="""
int trace_rename(struct pt_regs *ctx, struct renamedata *rd)
{
    struct dentry *old_dentry = rd->old_dentry;
    struct dentry *new_dentry = rd->new_dentry;
"""

bpf_vfs_unlink_text_old="""
int trace_unlink(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
"""
bpf_vfs_unlink_text_new="""
int trace_unlink(struct pt_regs *ctx, struct user_namespace *ns, struct inode *dir, struct dentry *dentry)
"""

def action2str(action):
    if chr(action) == 'D':
        action_str = "DELETE"
    else:
        action_str = "RENAME"
    return action_str

if args.pid:
    bpf_text = bpf_text.replace('FILTER',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '')

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# check 'struct renamedata' exist or not
if BPF.kernel_struct_has_field("renamedata", "old_mnt_userns") == 1:
    bpf_text = bpf_text.replace('TRACE_VFS_RENAME_FUNC', bpf_vfs_rename_text_new)
    bpf_text = bpf_text.replace('TRACE_VFS_UNLINK_FUNC', bpf_vfs_unlink_text_new)
else:
    bpf_text = bpf_text.replace('TRACE_VFS_RENAME_FUNC', bpf_vfs_rename_text_old)
    bpf_text = bpf_text.replace('TRACE_VFS_UNLINK_FUNC', bpf_vfs_unlink_text_old)

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="vfs_unlink", fn_name="trace_unlink")
b.attach_kprobe(event="vfs_rmdir", fn_name="trace_unlink")
b.attach_kprobe(event="vfs_rename", fn_name="trace_rename")

# header
print("%-8s %-7s %-16s %6s %s" % ("TIME", "PID", "COMM", "ACTION", "FILE"))

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    action_str = action2str(event.action)
    file_str = event.fname.decode('utf-8', 'replace')
    if action_str == "RENAME":
        file_str = "%s > %s" % (file_str, event.fname2.decode('utf-8', 'replace'))
    print("%-8s %-7d %-16s %6s %s" % (strftime("%H:%M:%S"), event.pid,
        event.comm.decode('utf-8', 'replace'), action_str, file_str))

b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

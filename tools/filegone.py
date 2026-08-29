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
# 05-Nov-2023 Rong Tao Support rename/unlink failed situation.
# 01-Jul-2025 Rong Tao Support file path

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime

# arguments
examples = """examples:
    ./filegone           # trace all file gone events
    ./filegone -P        # show file path
    ./filegone -p 181    # only trace PID 181
"""
parser = argparse.ArgumentParser(
    description="Trace why file gone (deleted or renamed)",
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
#include <linux/fs_struct.h>
#include <linux/sched.h>
#ifdef FULLPATH
INCLUDE_FULL_PATH_H
INCLUDE_PATH_HELPERS_BPF_H
#endif

struct data_t {
    u32 pid;
    u8 action;
    char comm[TASK_COMM_LEN];
    u32 path_depth, path_depth2;
#ifdef FULLPATH
    FULL_PATH_FIELD(fname);
    FULL_PATH_FIELD(fname2);
#else
    char fname[NAME_MAX];
    char fname2[NAME_MAX];
#endif
};

struct entry_t {
    u32 pid;
    u8 action;
    struct {
        char name[DNAME_INLINE_LEN];
        struct dentry *dentry;
    } old, new;
};

BPF_RINGBUF_OUTPUT(events, 64);
BPF_HASH(currentry, u32, struct entry_t);

static inline void get_dentry_name(char **name, struct dentry *dentry)
{
    struct qstr d_name = dentry->d_name;
    if (d_name.len == 0)
        return;
    bpf_probe_read_kernel(&data.fname, sizeof(data.fname), d_name.name);
}

// trace file deletion and output details
TRACE_VFS_UNLINK_FUNC
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    FILTER

    struct entry_t entry = {};

    entry.pid = pid;
    entry.action = 'D';
    entry.old.dentry = dentry;
    get_dentry_name((char **)&entry.old.name, dentry);

    currentry.update(&tid, &entry);

    return 0;
}

// trace file rename
TRACE_VFS_RENAME_FUNC

    struct entry_t entry = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    FILTER

    entry.pid = pid;
    entry.action = 'R';

    /**
     * Couldn't get new and old dentry name in trace_return(), because you'll
     * get new-name for old.
     */
    entry.old.dentry = old_dentry;
    get_dentry_name((char **)&entry.old.name, old_dentry);
    entry.new.dentry = new_dentry;
    get_dentry_name((char **)&entry.new.name, new_dentry);

    currentry.update(&tid, &entry);

    return 0;
}

int trace_return(struct pt_regs *ctx)
{
    struct data_t *data;
    struct entry_t *entry;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    int ret = PT_REGS_RC(ctx);

    entry = currentry.lookup(&tid);
    if (entry == 0)
        return 0;

    currentry.delete(&tid);

    /* Skip failed */
    if (ret)
        return 0;

    data = events.ringbuf_reserve(sizeof(struct data_t));
    if (!data)
        return 0;

    data->pid = entry->pid;
    data->action = entry->action;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    bpf_probe_read(&data->fname, sizeof(data->fname), entry->old.name);

    data->path_depth = data->path_depth2 = 0;
    if (entry->action == 'R')
        bpf_probe_read(&data->fname2, sizeof(data->fname2), entry->new.name);

#ifdef FULLPATH
    struct task_struct *task;
    struct fs_struct *fs;
    struct vfsmount *cwd_vfsmnt;

    task = (struct task_struct *)bpf_get_current_task_btf();
    bpf_probe_read_kernel(&fs, sizeof(fs), &task->fs);
    bpf_probe_read_kernel(&cwd_vfsmnt, sizeof(cwd_vfsmnt), &fs->pwd.mnt);
    if (data->fname[0] != '/') {
        data->path_depth = 1;
        bpf_dentry_full_path(data->fname + NAME_MAX, NAME_MAX, MAX_ENTRIES - 1,
                             entry->old.dentry->d_parent, cwd_vfsmnt,
                             &data->path_depth);
    }

    if (entry->action == 'R' && data->fname2[0] != '/') {
        data->path_depth2 = 1;
        bpf_dentry_full_path(data->fname2 + NAME_MAX, NAME_MAX, MAX_ENTRIES - 1,
                             entry->new.dentry->d_parent, cwd_vfsmnt,
                             &data->path_depth2);
    }
#endif

    events.ringbuf_submit(data, sizeof(*data));
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

bpf_vfs_unlink_text_1="""
int trace_unlink(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
"""
bpf_vfs_unlink_text_2="""
int trace_unlink(struct pt_regs *ctx, struct user_namespace *ns, struct inode *dir, struct dentry *dentry)
"""
bpf_vfs_unlink_text_3="""
int trace_unlink(struct pt_regs *ctx, struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry)
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

# check 'struct renamedata' exist or not
if BPF.kernel_struct_has_field(b'renamedata', b'new_mnt_idmap') == 1:
    bpf_text = bpf_text.replace('TRACE_VFS_RENAME_FUNC', bpf_vfs_rename_text_new)
    bpf_text = bpf_text.replace('TRACE_VFS_UNLINK_FUNC', bpf_vfs_unlink_text_3)
elif BPF.kernel_struct_has_field("renamedata", "old_mnt_userns") == 1:
    bpf_text = bpf_text.replace('TRACE_VFS_RENAME_FUNC', bpf_vfs_rename_text_new)
    bpf_text = bpf_text.replace('TRACE_VFS_UNLINK_FUNC', bpf_vfs_unlink_text_2)
else:
    bpf_text = bpf_text.replace('TRACE_VFS_RENAME_FUNC', bpf_vfs_rename_text_old)
    bpf_text = bpf_text.replace('TRACE_VFS_UNLINK_FUNC', bpf_vfs_unlink_text_1)

if args.path:
    bpf_text = "#define FULLPATH\n" + bpf_text

    with open(BPF._find_file("full_path.h".encode("utf-8"))) as fileobj:
        progtxt = fileobj.read()
    bpf_text = bpf_text.replace('INCLUDE_FULL_PATH_H', progtxt)

    with open(BPF._find_file("path_helpers.bpf.c".encode("utf-8"))) as fileobj:
        progtxt = fileobj.read()
    bpf_text = bpf_text.replace('INCLUDE_PATH_HELPERS_BPF_H', progtxt)

# NOTE: After bpf_text modification
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="vfs_unlink", fn_name="trace_unlink")
b.attach_kprobe(event="vfs_rmdir", fn_name="trace_unlink")
b.attach_kprobe(event="vfs_rename", fn_name="trace_rename")
b.attach_kretprobe(event="vfs_unlink", fn_name="trace_return")
b.attach_kretprobe(event="vfs_rmdir", fn_name="trace_return")
b.attach_kretprobe(event="vfs_rename", fn_name="trace_return")

# header
print("%-8s %-7s %-16s %6s %s" % ("TIME", "PID", "COMM", "ACTION", "FILE"))

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    action_str = action2str(event.action)
    if args.path:
        import os
        import sys
        sys.path.append(os.path.dirname(sys.argv[0]))
        from path_helpers import get_full_path
        file_str = get_full_path(event.fname, event.path_depth)
        if action_str == "RENAME":
            file2_str = get_full_path(event.fname2, event.path_depth2)
            file_str = "%s > %s" % (file_str, file2_str)
    else:
        file_str = event.fname.decode('utf-8', 'replace')
        if action_str == "RENAME":
            file2_str = event.fname2.decode('utf-8', 'replace')
            file_str = "%s > %s" % (file_str, file2_str)
    print("%-8s %-7d %-16s %6s %s" % (strftime("%H:%M:%S"), event.pid,
        event.comm.decode('utf-8', 'replace'), action_str, file_str))

b["events"].open_ring_buffer(print_event)
while 1:
    try:
        b.ring_buffer_poll()
    except KeyboardInterrupt:
        exit()

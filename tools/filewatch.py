#!/usr/bin/python3
# @lint-avoid-python-3-compatibility-imports
#
# filewatch    Watch a file or directory tree for VFS reads, writes,
#              metadata changes, creation, and deletion, then dump
#              the full process ancestry with command lines.
#              For Linux, uses BCC, eBPF. Embedded C.
#
# Filesystem-agnostic: hooks the VFS layer, so it works on ext4,
# btrfs, ZFS (OpenZFS), VxFS, XFS, tmpfs, NFS, ...
#
# Matches by inode+device -- immune to bind mounts, hardlinks, and
# relative-path tricks.  When pointed at a directory, walks the
# dentry parent chain in-kernel so files at any depth are caught.
#
# The caller's own cmdline is captured inside the BPF probe
# (via mm->arg_start), so even a short-lived "bash -c '...'" that
# exits right after the I/O is fully recorded.  Parent processes
# are enriched from /proc in userspace.
#
# USAGE: filewatch [-h] [-r] [-w] [-m] [-c] [-u] [-a] [-k]
#                  [-d SEC] [--ebpf] path
#
# Copyright (c) 2026 Vincent S. Cojot.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 26-Aug-2026   Vincent S. Cojot   Created this.

from __future__ import print_function
from bcc import BPF
import argparse
import ctypes as ct
import os
import pwd
import re
import stat
import sys
import time

MAX_ANCESTORS = 20
MAX_DIR_DEPTH = 24
MAX_PATH_COMP = 8
PATH_COMP_LEN = 48

# ── BPF C program ───────────────────────────────────────────────────
bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <linux/build_bug.h>

/* Kernel 7.x has static_assert checks in fs.h that fail under   */
/* BCC Clang.  Override after build_bug.h sets its include guard. */
#undef static_assert
#define static_assert(expr, ...)

#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/mm_types.h>

struct iovec;  /* forward-decl avoids -Wvisibility in readv/writev */

#define MAX_ANCESTORS  MAXANC_PLACEHOLDER
#define MAX_DIR_DEPTH  MAXDIRDEPTH_PLACEHOLDER
#define MAX_PATH_COMP  8
#define PATH_COMP_LEN  48

#define OP_READ   1
#define OP_WRITE  2
#define OP_META   3
#define OP_CREATE 4
#define OP_DELETE 5

struct ancestor_t {
    u32 tgid;
    char comm[TASK_COMM_LEN];
};

struct event_t {
    u64  ts_ns;
    u32  pid;
    u32  tid;
    u32  uid;
    u64  bytes;           /* byte count for r/w, ia_valid for meta */
    u8   op;
    u32  depth;
    char fname[64];
    char dirpath[64];
    char caller_cmdline[256];
    struct ancestor_t chain[MAX_ANCESTORS];
    int kstack_id;
    u32 npath;
    char fpath[MAX_PATH_COMP][PATH_COMP_LEN];
};

BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(heap, struct event_t, 1);
STACK_TABLE_PLACEHOLDER

/* ── match target by inode+dev ─────────────────────────────────── */
static __always_inline int
check_match(struct dentry *dentry)
{
    MATCH_CHECK_PLACEHOLDER
}

/* ── fill common event fields ──────────────────────────────────── */
static __always_inline void
fill_event(struct event_t *event, struct dentry *de, u8 op)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid   = pid_tgid >> 32;
    event->tid   = (u32)pid_tgid;
    event->uid   = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->op    = op;
    event->ts_ns = bpf_ktime_get_ns();

    bpf_probe_read_kernel_str(&event->fname, sizeof(event->fname),
                              de->d_name.name);

    struct dentry *pde = de->d_parent;
    if (pde && pde != de)
        bpf_probe_read_kernel_str(&event->dirpath,
                                  sizeof(event->dirpath),
                                  pde->d_name.name);

    /* --- caller cmdline, captured in-kernel (race-free) ---------- */
    struct task_struct *curr =
        (struct task_struct *)bpf_get_current_task();
    struct mm_struct *mm = NULL;
    bpf_probe_read_kernel(&mm, sizeof(mm), &curr->mm);
    if (mm) {
        unsigned long arg_start = 0, arg_end = 0;
        bpf_probe_read_kernel(&arg_start, sizeof(arg_start),
                              &mm->arg_start);
        bpf_probe_read_kernel(&arg_end, sizeof(arg_end),
                              &mm->arg_end);
        long len = arg_end - arg_start;
        if (len > 0) {
            if (len > (long)sizeof(event->caller_cmdline) - 1)
                len = sizeof(event->caller_cmdline) - 1;
            bpf_probe_read_user(event->caller_cmdline, len,
                                (void *)arg_start);
        }
    }

    /* --- walk process ancestry ----------------------------------- */
    struct task_struct *task = curr;
    int done = 0;
    #pragma unroll
    for (int i = 0; i < MAX_ANCESTORS; i++) {
        if (!done && task) {
            event->chain[i].tgid = task->tgid;
            bpf_probe_read_kernel_str(
                &event->chain[i].comm,
                sizeof(event->chain[i].comm),
                task->comm);
            event->depth = i + 1;
            if (task->tgid <= 1) {
                done = 1;
            } else {
                bpf_probe_read_kernel(&task, sizeof(task),
                                      &task->real_parent);
            }
        }
    }

    /* --- walk dentry chain for full path (child -> root) ---------- */
    struct dentry *_walk = de;
    int _wdone = 0;
    #pragma unroll
    for (int _i = 0; _i < MAX_PATH_COMP; _i++) {
        if (!_wdone && _walk) {
            bpf_probe_read_kernel_str(
                &event->fpath[_i], PATH_COMP_LEN,
                _walk->d_name.name);
            event->npath = _i + 1;
            struct dentry *_wp = _walk->d_parent;
            if (_wp == _walk) {
                _wdone = 1;
            } else {
                _walk = _wp;
            }
        }
    }
}

/* ── data read/write path ────────────────────────────────────────── */
static __always_inline int
do_trace(struct pt_regs *ctx, struct file *file, u64 count, u8 op)
{
    struct dentry *de = file->f_path.dentry;
    if (!check_match(de))
        return 0;

    int zero = 0;
    struct event_t *event = heap.lookup(&zero);
    if (!event)
        return 0;
    event->fname[0] = '\0';
    event->dirpath[0] = '\0';
    event->caller_cmdline[0] = '\0';
    event->depth = 0;
    event->npath = 0;
    event->kstack_id = -1;

    event->bytes = count;
    fill_event(event, de, op);
    STACK_CAPTURE_PLACEHOLDER
    events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

/* ── metadata path (notify_change) ───────────────────────────────── */
static __always_inline int
do_trace_meta(struct pt_regs *ctx, struct dentry *dentry,
              unsigned int ia_valid)
{
    if (!check_match(dentry))
        return 0;

    int zero = 0;
    struct event_t *event = heap.lookup(&zero);
    if (!event)
        return 0;
    event->fname[0] = '\0';
    event->dirpath[0] = '\0';
    event->caller_cmdline[0] = '\0';
    event->depth = 0;
    event->npath = 0;
    event->kstack_id = -1;

    event->bytes = (u64)ia_valid;
    fill_event(event, dentry, OP_META);
    STACK_CAPTURE_PLACEHOLDER
    events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

/* ── read probes ─────────────────────────────────────────────────── */

int trace_vfs_read(struct pt_regs *ctx, struct file *file,
                   char __user *buf, size_t count)
{
    return do_trace(ctx, file, (u64)count, OP_READ);
}

int trace_vfs_readv(struct pt_regs *ctx, struct file *file,
                    const struct iovec __user *vec,
                    unsigned long vlen)
{
    return do_trace(ctx, file, (u64)vlen, OP_READ);
}

/* ── write probes ────────────────────────────────────────────────── */

int trace_vfs_write(struct pt_regs *ctx, struct file *file,
                    char __user *buf, size_t count)
{
    return do_trace(ctx, file, (u64)count, OP_WRITE);
}

int trace_vfs_writev(struct pt_regs *ctx, struct file *file,
                     const struct iovec __user *vec,
                     unsigned long vlen)
{
    return do_trace(ctx, file, (u64)vlen, OP_WRITE);
}

/* ── metadata probe (touch, chmod, chown, truncate) ──────────────── */

int trace_notify_change(struct pt_regs *ctx)
{
    struct dentry *dentry =
        (struct dentry *)NOTIFY_PARM_DENTRY_PLACEHOLDER(ctx);
    struct iattr *attr =
        (struct iattr *)NOTIFY_PARM_ATTR_PLACEHOLDER(ctx);
    unsigned int ia_valid = attr->ia_valid;
    return do_trace_meta(ctx, dentry, ia_valid);
}

/* ── lifecycle match (creation: dentry->d_inode is NULL) ─────────── */
static __always_inline int
check_match_create(struct dentry *dentry)
{
    MATCH_CREATE_CHECK_PLACEHOLDER
}

/* ── lifecycle path (create / delete) ────────────────────────────── */
static __always_inline int
do_trace_lifecycle(struct pt_regs *ctx, struct dentry *dentry, u8 op)
{
    if (op == OP_CREATE) {
        if (!check_match_create(dentry))
            return 0;
    } else {
        if (!check_match(dentry))
            return 0;
    }

    int zero = 0;
    struct event_t *event = heap.lookup(&zero);
    if (!event)
        return 0;
    event->fname[0] = '\0';
    event->dirpath[0] = '\0';
    event->caller_cmdline[0] = '\0';
    event->depth = 0;
    event->npath = 0;
    event->kstack_id = -1;

    event->bytes = 0;
    fill_event(event, dentry, op);
    STACK_CAPTURE_PLACEHOLDER
    events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

/* ── create probe (security_inode_create) ─────────────────────────── */

int trace_security_create(struct pt_regs *ctx)
{
    struct dentry *dentry =
        (struct dentry *)PT_REGS_PARM2(ctx);
    return do_trace_lifecycle(ctx, dentry, OP_CREATE);
}

/* ── delete probe (security_inode_unlink) ─────────────────────────── */

int trace_security_unlink(struct pt_regs *ctx)
{
    struct dentry *dentry =
        (struct dentry *)PT_REGS_PARM2(ctx);
    return do_trace_lifecycle(ctx, dentry, OP_DELETE);
}

/* ── mkdir probe (security_inode_mkdir) ───────────────────────────── */

int trace_security_mkdir(struct pt_regs *ctx)
{
    struct dentry *dentry =
        (struct dentry *)PT_REGS_PARM2(ctx);
    return do_trace_lifecycle(ctx, dentry, OP_CREATE);
}

/* ── rmdir probe (security_inode_rmdir) ───────────────────────────── */

int trace_security_rmdir(struct pt_regs *ctx)
{
    struct dentry *dentry =
        (struct dentry *)PT_REGS_PARM2(ctx);
    return do_trace_lifecycle(ctx, dentry, OP_DELETE);
}
"""

# ── match-check C fragments ────────────────────────────────────────
# Injected into check_match().  Must "return 0" on miss, "return 1"
# on hit.

MATCH_FILE = r"""
    u64 _ino = dentry->d_inode->i_ino;
    dev_t _dev = dentry->d_inode->i_sb->s_dev;
    if (_ino != TARGET_INO_PLACEHOLDER ||
        _dev != TARGET_DEV_PLACEHOLDER)
        return 0;
    return 1;
"""

MATCH_DIR = r"""
    dev_t _dev = dentry->d_inode->i_sb->s_dev;
    if (_dev != TARGET_DEV_PLACEHOLDER)
        return 0;
    struct dentry *_d = dentry;
    int _matched = 0;
    #pragma unroll
    for (int _i = 0; _i < MAX_DIR_DEPTH; _i++) {
        if (!_matched && _d) {
            if (_d->d_inode->i_ino == TARGET_INO_PLACEHOLDER) {
                _matched = 1;
            } else {
                struct dentry *_p = _d->d_parent;
                if (_p == _d)
                    _matched = -1;
                _d = _p;
            }
        }
    }
    return (_matched == 1) ? 1 : 0;
"""

MATCH_FILE_CREATE = r"""
    /* Single-file mode: creation events not applicable. */
    return 0;
"""

MATCH_DIR_CREATE = r"""
    /* For creation, dentry->d_inode is NULL -- walk from parent. */
    struct dentry *_parent = dentry->d_parent;
    if (!_parent) return 0;
    dev_t _dev = _parent->d_inode->i_sb->s_dev;
    if (_dev != TARGET_DEV_PLACEHOLDER)
        return 0;
    struct dentry *_d = _parent;
    int _matched = 0;
    #pragma unroll
    for (int _i = 0; _i < MAX_DIR_DEPTH; _i++) {
        if (!_matched && _d) {
            if (_d->d_inode->i_ino == TARGET_INO_PLACEHOLDER) {
                _matched = 1;
            } else {
                struct dentry *_p = _d->d_parent;
                if (_p == _d)
                    _matched = -1;
                _d = _p;
            }
        }
    }
    return (_matched == 1) ? 1 : 0;
"""

# ── constants ───────────────────────────────────────────────────────
OP_READ   = 1
OP_WRITE  = 2
OP_META   = 3
OP_CREATE = 4
OP_DELETE = 5
OP_LABEL = {
    OP_READ: "READ", OP_WRITE: "WRITE", OP_META: "META",
    OP_CREATE: "CREATE", OP_DELETE: "UNLINK",
}

TASK_COMM_LEN = 16

ATTR_FLAGS = [
    (0x0001, "MODE"),       # chmod
    (0x0002, "UID"),        # chown
    (0x0004, "GID"),        # chgrp
    (0x0008, "SIZE"),       # truncate
    (0x0010, "ATIME"),      # access time
    (0x0020, "MTIME"),      # modification time
    (0x0040, "CTIME"),      # change time
    (0x0080, "ATIME_SET"),  # utimes (explicit)
    (0x0100, "MTIME_SET"),  # utimes (explicit)
]


# Manual ctypes layout -- BCC can't auto-detect struct arrays.
class AncestorT(ct.Structure):
    _fields_ = [
        ("tgid", ct.c_uint32),
        ("comm", ct.c_char * TASK_COMM_LEN),
    ]


class EventT(ct.Structure):
    _fields_ = [
        ("ts_ns",           ct.c_uint64),
        ("pid",             ct.c_uint32),
        ("tid",             ct.c_uint32),
        ("uid",             ct.c_uint32),
        ("bytes",           ct.c_uint64),
        ("op",              ct.c_uint8),
        ("depth",           ct.c_uint32),
        ("fname",           ct.c_char * 64),
        ("dirpath",         ct.c_char * 64),
        ("caller_cmdline",  ct.c_char * 256),
        ("chain",           AncestorT * MAX_ANCESTORS),
        ("kstack_id",       ct.c_int32),
        ("npath",           ct.c_uint32),
        ("fpath",           (ct.c_char * PATH_COMP_LEN)
                            * MAX_PATH_COMP),
    ]


# ── helpers ─────────────────────────────────────────────────────────
def _kernel_version():
    """Return (major, minor) from uname release string."""
    m = re.match(r"(\d+)\.(\d+)", os.uname().release)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def _resolve_sb_dev(path):
    """Return (major, minor) of the superblock device for *path*.

    Filesystems like btrfs and ZFS override stat()->st_dev to a
    per-subvolume anonymous device, which differs from the kernel's
    i_sb->s_dev.  /proc/self/mountinfo always reports s_dev, so we
    parse that to get the value the BPF probe will see.
    """
    abs_path = os.path.realpath(path)
    best_mount = ""
    best_major = -1
    best_minor = -1
    try:
        with open("/proc/self/mountinfo") as f:
            for line in f:
                parts = line.split()
                mount_point = parts[4]
                if mount_point == "/":
                    matches = abs_path.startswith("/")
                else:
                    matches = (abs_path == mount_point or
                               abs_path.startswith(mount_point + "/"))
                if matches and len(mount_point) > len(best_mount):
                    best_mount = mount_point
                    maj, mn = parts[2].split(":")
                    best_major, best_minor = int(maj), int(mn)
    except (OSError, ValueError, IndexError):
        pass
    if best_major < 0:
        st = os.stat(path)
        best_major = os.major(st.st_dev)
        best_minor = os.minor(st.st_dev)
    return best_major, best_minor


def decode_ia_valid(val):
    """Decode an iattr ia_valid bitmask to human-readable labels."""
    parts = []
    for mask, name in ATTR_FLAGS:
        if val & mask:
            parts.append(name)
    return "|".join(parts) if parts else "0x%x" % val


def read_proc(pid, entry):
    """Read /proc/PID/{cmdline,exe,cwd}.  Returns None on failure."""
    try:
        if entry == "cmdline":
            with open("/proc/%d/cmdline" % pid, "rb") as f:
                raw = f.read()
                if not raw:
                    return None
                return (raw.replace(b"\0", b" ")
                        .decode("utf-8", "replace").strip()) or None
        else:
            return os.readlink("/proc/%d/%s" % (pid, entry))
    except (FileNotFoundError, PermissionError,
            ProcessLookupError, OSError):
        return None


def uid_to_name(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def build_bpf(target_ino, target_dev, dir_mode, want_stacks):
    """Substitute placeholders in the BPF C source."""
    src = bpf_text

    src = src.replace("MAXANC_PLACEHOLDER", str(MAX_ANCESTORS))
    src = src.replace("MAXDIRDEPTH_PLACEHOLDER", str(MAX_DIR_DEPTH))

    src = src.replace("TARGET_INO_PLACEHOLDER", str(target_ino))
    src = src.replace("TARGET_DEV_PLACEHOLDER", str(target_dev))

    match_code = MATCH_DIR if dir_mode else MATCH_FILE
    match_code = match_code.replace(
        "TARGET_INO_PLACEHOLDER", str(target_ino))
    match_code = match_code.replace(
        "TARGET_DEV_PLACEHOLDER", str(target_dev))
    src = src.replace("MATCH_CHECK_PLACEHOLDER", match_code)

    match_create = MATCH_DIR_CREATE if dir_mode else MATCH_FILE_CREATE
    match_create = match_create.replace(
        "TARGET_INO_PLACEHOLDER", str(target_ino))
    match_create = match_create.replace(
        "TARGET_DEV_PLACEHOLDER", str(target_dev))
    src = src.replace("MATCH_CREATE_CHECK_PLACEHOLDER", match_create)

    kver = _kernel_version()
    if kver >= (5, 12):
        src = src.replace("NOTIFY_PARM_DENTRY_PLACEHOLDER",
                          "PT_REGS_PARM2")
        src = src.replace("NOTIFY_PARM_ATTR_PLACEHOLDER",
                          "PT_REGS_PARM3")
    else:
        src = src.replace("NOTIFY_PARM_DENTRY_PLACEHOLDER",
                          "PT_REGS_PARM1")
        src = src.replace("NOTIFY_PARM_ATTR_PLACEHOLDER",
                          "PT_REGS_PARM2")

    if want_stacks:
        src = src.replace(
            "STACK_TABLE_PLACEHOLDER",
            "BPF_STACK_TRACE(stack_traces, 1024);")
        src = src.replace(
            "STACK_CAPTURE_PLACEHOLDER",
            "event->kstack_id = stack_traces.get_stackid("
            "ctx, BPF_F_REUSE_STACKID);")
    else:
        src = src.replace("STACK_TABLE_PLACEHOLDER", "")
        src = src.replace("STACK_CAPTURE_PLACEHOLDER", "")

    return src


# ── argument parsing ────────────────────────────────────────────────
examples = """examples:
    ./filewatch /etc/fstab            # watch one file (writes)
    ./filewatch /etc/                 # watch entire /etc/ tree
    ./filewatch -rw /etc/             # reads + writes, tree
    ./filewatch -r  /etc/shadow       # reads only, one file
    ./filewatch -m  /etc/passwd       # metadata (touch/chmod/...)
    ./filewatch -c  /tmp/             # creation only (dir mode)
    ./filewatch -u  /etc/hosts        # unlink only
    ./filewatch -a  /etc/             # all: r+w+m+create+unlink
    ./filewatch -w  /path -d 1.0      # writes, debounce 1s
    ./filewatch -rwk /etc/hosts       # include kernel stacks
"""

parser = argparse.ArgumentParser(
    description="Watch a file or directory tree for VFS access and "
    "dump the full process ancestry with command lines.  Works on "
    "any filesystem (ext4, btrfs, ZFS, VxFS, XFS, NFS, ...).",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("path",
    help="file or directory to watch (directories are recursive)")
parser.add_argument("-r", "--reads", action="store_true",
    help="trace reads (vfs_read / vfs_readv)")
parser.add_argument("-w", "--writes", action="store_true",
    help="trace writes (vfs_write / vfs_writev)")
parser.add_argument("-m", "--meta", action="store_true",
    help="trace metadata changes: touch, chmod, chown, truncate")
parser.add_argument("-c", "--create", action="store_true",
    help="trace file/directory creation (directory mode only)")
parser.add_argument("-u", "--unlink", action="store_true",
    help="trace file/directory deletion (unlink/rmdir)")
parser.add_argument("-a", "--all", action="store_true",
    help="trace everything: reads + writes + metadata + create "
         "+ unlink")
parser.add_argument("-d", "--debounce", type=float, default=0.0,
    metavar="SEC",
    help="minimum seconds between reports for same PID+op "
         "(default: 0 = every event)")
parser.add_argument("-k", "--kstack", action="store_true",
    help="capture and display kernel stack traces")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

if args.all:
    args.reads = args.writes = args.meta = True
    args.create = args.unlink = True
if (not args.reads and not args.writes and not args.meta
        and not args.create and not args.unlink):
    args.writes = True

if os.geteuid() != 0:
    print("error: must be run as root (for BPF)", file=sys.stderr)
    exit(1)

filter_name = None
try:
    st = os.stat(args.path)
except FileNotFoundError:
    parent = os.path.dirname(os.path.abspath(args.path))
    basename = os.path.basename(os.path.abspath(args.path))
    try:
        st = os.stat(parent)
    except (FileNotFoundError, PermissionError):
        print("error: %s: not found and parent dir "
              "does not exist" % args.path, file=sys.stderr)
        exit(1)
    if not stat.S_ISDIR(st.st_mode):
        print("error: %s: not found" % args.path, file=sys.stderr)
        exit(1)
    args.path = parent
    args.create = True
    filter_name = basename
except PermissionError:
    print("error: %s: permission denied" % args.path,
          file=sys.stderr)
    exit(1)

dir_mode = stat.S_ISDIR(st.st_mode)

if args.create and not dir_mode:
    print("  *** -c/--create ignored for file targets "
          "(use a directory for creation tracing) ***",
          file=sys.stderr)
    args.create = False

target_ino = st.st_ino
st_major, st_minor = _resolve_sb_dev(args.path)
target_dev = (st_major << 20) | st_minor
abs_path = os.path.abspath(args.path)

modes = []
if args.reads:
    modes.append("reads")
if args.writes:
    modes.append("writes")
if args.meta:
    modes.append("metadata")
if args.create and dir_mode:
    modes.append("create")
if args.unlink:
    modes.append("unlink")

print("filewatch - VFS file access tracer")
if dir_mode:
    print("  dir   : %s  (recursive)" % abs_path)
else:
    print("  file  : %s" % abs_path)
print("  inode : %d" % target_ino)
print("  dev   : major=%d, minor=%d (kernel_dev=%d)" % (
    st_major, st_minor, target_dev))
print("  mode  : %s" % " + ".join(modes))
if dir_mode:
    print("  depth : up to %d levels" % MAX_DIR_DEPTH)
if filter_name:
    print("  filter: %s (waiting for creation)" % filter_name)
if args.debounce > 0:
    print("  debounce: %.1fs per PID" % args.debounce)
print("Hit Ctrl-C to end.\n")

print("Loading probes...")
src = build_bpf(target_ino, target_dev, dir_mode, args.kstack)

if args.ebpf:
    print(src)
    exit()

b = BPF(text=src,
        cflags=["-Wno-missing-declarations"])

attached = []
if args.reads:
    b.attach_kprobe(event="vfs_read", fn_name="trace_vfs_read")
    attached.append("vfs_read")
    try:
        b.attach_kprobe(event="vfs_readv",
                        fn_name="trace_vfs_readv")
        attached.append("vfs_readv")
    except Exception:
        pass
if args.writes:
    b.attach_kprobe(event="vfs_write", fn_name="trace_vfs_write")
    attached.append("vfs_write")
    try:
        b.attach_kprobe(event="vfs_writev",
                        fn_name="trace_vfs_writev")
        attached.append("vfs_writev")
    except Exception:
        pass
if args.meta:
    try:
        b.attach_kprobe(event="notify_change",
                        fn_name="trace_notify_change")
        attached.append("notify_change")
    except Exception as e:
        print("warning: could not attach to notify_change: %s" %
              e, file=sys.stderr)
        print("  metadata tracing (-m) will not work on this "
              "kernel", file=sys.stderr)
if args.create and dir_mode:
    try:
        b.attach_kprobe(event="security_inode_create",
                        fn_name="trace_security_create")
        attached.append("security_inode_create")
    except Exception as e:
        print("warning: could not attach to "
              "security_inode_create: %s" % e,
              file=sys.stderr)
    try:
        b.attach_kprobe(event="security_inode_mkdir",
                        fn_name="trace_security_mkdir")
        attached.append("security_inode_mkdir")
    except Exception as e:
        print("warning: could not attach to "
              "security_inode_mkdir: %s" % e,
              file=sys.stderr)
if args.unlink:
    try:
        b.attach_kprobe(event="security_inode_unlink",
                        fn_name="trace_security_unlink")
        attached.append("security_inode_unlink")
    except Exception as e:
        print("warning: could not attach to "
              "security_inode_unlink: %s" % e,
              file=sys.stderr)
    try:
        b.attach_kprobe(event="security_inode_rmdir",
                        fn_name="trace_security_rmdir")
        attached.append("security_inode_rmdir")
    except Exception as e:
        print("warning: could not attach to "
              "security_inode_rmdir: %s" % e,
              file=sys.stderr)

print("Attached probes: %s" % ", ".join(attached))
print()

last_seen = {}
exiting = [False]


def print_event(cpu, data, size):
    ev = ct.cast(data, ct.POINTER(EventT)).contents
    now = time.time()

    if filter_name:
        evname = ev.fname.decode("utf-8", "replace")
        if evname != filter_name:
            return

    if args.debounce > 0:
        key = (ev.pid, ev.op)
        prev = last_seen.get(key, 0)
        if now - prev < args.debounce:
            return
        last_seen[key] = now

    ts = time.strftime("%H:%M:%S")
    fname = ev.fname.decode("utf-8", "replace")
    dirpath = ev.dirpath.decode("utf-8", "replace")
    user = uid_to_name(ev.uid)
    op = OP_LABEL.get(ev.op, "?")

    if dir_mode and dirpath and dirpath != "/":
        display_path = "%s/%s" % (dirpath, fname)
    else:
        display_path = fname

    full_path = ""
    if ev.npath > 0:
        parts = []
        for i in range(ev.npath):
            comp = ev.fpath[i].value.decode("utf-8", "replace")
            if comp and comp != "/":
                parts.append(comp)
        parts.reverse()
        full_path = "/" + "/".join(parts)
    elif not dir_mode:
        full_path = abs_path

    raw = ev.caller_cmdline
    bpf_cmdline = (raw.replace(b"\0", b" ")
                   .decode("utf-8", "replace").strip()) or None

    print("=" * 72)
    if ev.op == OP_META:
        attrs = decode_ia_valid(ev.bytes)
        print("%-6s %s  file=%s  attrs=%s  user=%s" % (
            op, ts, display_path, attrs, user))
    elif ev.op in (OP_CREATE, OP_DELETE):
        print("%-6s %s  file=%s  user=%s" % (
            op, ts, display_path, user))
    else:
        print("%-6s %s  file=%s  bytes=%d  user=%s" % (
            op, ts, display_path, ev.bytes, user))
    if full_path:
        print("       path: %s" % full_path)
    target_unlinked = False
    if ev.op == OP_DELETE:
        if not dir_mode:
            if fname == os.path.basename(abs_path):
                target_unlinked = True
        elif full_path and full_path == abs_path:
            target_unlinked = True
    print("Process tree (caller first):\n")

    for i in range(ev.depth):
        a = ev.chain[i]
        pid  = a.tgid
        comm = a.comm.decode("utf-8", "replace")

        if i == 0 and bpf_cmdline:
            cmdline = bpf_cmdline
        else:
            cmdline = read_proc(pid, "cmdline")

        exe = read_proc(pid, "exe")
        indent = "  " * i
        tag = ">>>" if i == 0 else "   "

        line = "%s %s[%d] %s" % (tag, indent, pid, comm)
        if cmdline and cmdline != comm:
            line += "\n    %scmdline: %s" % (indent, cmdline)
        if exe:
            line += "\n    %sexe:     %s" % (indent, exe)
        if i == 0:
            cwd = read_proc(pid, "cwd")
            if cwd:
                line += "\n    %scwd:     %s" % (indent, cwd)
        if pid <= 1:
            line += "  (init)"
        if read_proc(pid, "cmdline") is None and i > 0:
            line += "  [exited]"
        print(line)

    if args.kstack:
        try:
            stack_id = ev.kstack_id
            if stack_id >= 0:
                stack = list(b["stack_traces"].walk(stack_id))
                if stack:
                    print("\n    Kernel stack:")
                    for addr in stack:
                        sym = b.ksym(addr).decode(
                            "utf-8", "replace")
                        print("      %s" % sym)
        except Exception:
            pass

    print()

    if target_unlinked:
        print("  *** target was unlinked -- exiting ***")
        exiting[0] = True


b["events"].open_perf_buffer(print_event, page_cnt=64)

while not exiting[0]:
    try:
        b.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        exit()

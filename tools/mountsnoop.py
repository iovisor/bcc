#!/usr/bin/env python
#
# mountsnoop Trace mount() and umount syscalls.
#            For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: mountsnoop [-h]
#
# Copyright (c) 2016 Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Oct-2016   Omar Sandoval   Created this.
# 23-Jun-2024   Rong Tao        Add fsopen(2),fsconfig(2),fsmount(2),
#                               move_mount(2) syscalls support

from __future__ import print_function
import argparse
import bcc
from bcc.containers import filter_by_containers
import ctypes
import errno
import functools
import sys


bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#include <linux/nsproxy.h>
#include <linux/ns_common.h>

/*
 * XXX: struct mnt_namespace is defined in fs/mount.h, which is private to the
 * VFS and not installed in any kernel-devel packages. So, let's duplicate the
 * important part of the definition. There are actually more members in the
 * real struct, but we don't need them, and they're more likely to change.
 *
 * To add support for --selector option, we need to call filter_by_containers().
 * But this function adds code which defines struct mnt_namespace.
 * To avoid having this structure twice, we define MNT_NAMESPACE_DEFINED in
 * filter_by_containers(), then here we check if macro is already defined before
 * adding struct definition.
 */
#ifndef MNT_NAMESPACE_DEFINED
struct mnt_namespace {
    // This field was removed in https://github.com/torvalds/linux/commit/1a7b8969e664d6af328f00fe6eb7aabd61a71d13
    #if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
    atomic_t count;
    #endif
    struct ns_common ns;
};
#endif /* !MNT_NAMESPACE_DEFINED */

/*
 * XXX: this could really use first-class string support in BPF. target is a
 * NUL-terminated path up to PATH_MAX in length. source and type are
 * NUL-terminated strings up to PAGE_SIZE in length. data is a weird case: it's
 * almost always a NUL-terminated string, but for some filesystems (e.g., older
 * NFS variants), it's a binary structure with plenty of NUL bytes, so the
 * kernel always copies up to PAGE_SIZE bytes, stopping when it hits a fault.
 *
 * The best we can do with the existing BPF helpers is to copy as much of each
 * argument as we can. Our stack space is limited, and we need to leave some
 * headroom for the rest of the function, so this should be a decent value.
 */
#define MAX_STR_LEN 412

enum event_type {
    EVENT_MOUNT,
    EVENT_MOUNT_SOURCE,
    EVENT_MOUNT_TARGET,
    EVENT_MOUNT_TYPE,
    EVENT_MOUNT_DATA,
    EVENT_MOUNT_RET,
    EVENT_FSOPEN,
    EVENT_FSOPEN_FS_NAME,
    EVENT_FSOPEN_RET,
    EVENT_FSMOUNT,
    EVENT_FSMOUNT_PARAMS,
    EVENT_FSMOUNT_RET,
    EVENT_FSCONFIG,
    EVENT_FSCONFIG_PARAMS,
    EVENT_FSCONFIG_RET,
    EVENT_MOVE_MOUNT,
    EVENT_MOVE_MOUNT_PARAMS,
    EVENT_MOVE_MOUNT_RET,
    EVENT_UMOUNT,
    EVENT_UMOUNT_TARGET,
    EVENT_UMOUNT_RET,
};

struct data_t {
    enum event_type type;
    pid_t pid, tgid;
    union {
        /*
         * EVENT_MOUNT, EVENT_UMOUNT, EVENT_FSOPEN, EVENT_FSMOUNT,
         * EVENT_FSCONFIG, EVENT_MOVE_MOUNT
         */
        struct {
            /* current->nsproxy->mnt_ns->ns.inum */
            unsigned int mnt_ns;
            char comm[TASK_COMM_LEN];
            char pcomm[TASK_COMM_LEN];
            pid_t ppid;
            unsigned long flags;
        } enter;
        /*
         * EVENT_MOUNT_SOURCE, EVENT_MOUNT_TARGET, EVENT_MOUNT_TYPE,
         * EVENT_MOUNT_DATA, EVENT_UMOUNT_TARGET, EVENT_FSOPEN_FS_NAME
         */
        char str[MAX_STR_LEN];
        /* EVENT_FSMOUNT_PARAMS */
        struct {
            int fs_fd;
            int attr_flags;
        } fsmount;
        /* EVENT_FSCONFIG_PARAMS */
        struct {
            int fd;
            unsigned int cmd;
            char key[32];
            char value[32];
            int aux;
        } fsconfig;
        /* EVENT_MOVE_MOUNT_PARAMS */
        struct {
            int from_dfd;
            char from_pathname[128];
            int to_dfd;
            char to_pathname[128];
            unsigned int flags;
        } move_mount;
        /*
         * EVENT_MOUNT_RET, EVENT_UMOUNT_RET, EVENT_FSOPEN_RET,
         * EVENT_FSMOUNT_RET, EVENT_FSCONFIG_RET, EVENT_MOVE_MOUNT_RET
         */
        int retval;
    };
};

BPF_PERF_OUTPUT(events);

int syscall__mount(struct pt_regs *ctx, char __user *source,
                      char __user *target, char __user *type,
                      unsigned long flags, char __user *data)
{
    struct data_t event = {};
    struct task_struct *task;
    struct nsproxy *nsproxy;
    struct mnt_namespace *mnt_ns;

    if (container_should_be_filtered()) {
        return 0;
    }

    event.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    event.tgid = bpf_get_current_pid_tgid() >> 32;

    event.type = EVENT_MOUNT;
    bpf_get_current_comm(event.enter.comm, sizeof(event.enter.comm));
    event.enter.flags = flags;
    task = (struct task_struct *)bpf_get_current_task();
    event.enter.ppid = task->real_parent->tgid;
    bpf_probe_read_kernel_str(&event.enter.pcomm, TASK_COMM_LEN, task->real_parent->comm);
    nsproxy = task->nsproxy;
    mnt_ns = nsproxy->mnt_ns;
    event.enter.mnt_ns = mnt_ns->ns.inum;
    events.perf_submit(ctx, &event, sizeof(event));

    event.type = EVENT_MOUNT_SOURCE;
    __builtin_memset(event.str, 0, sizeof(event.str));
    bpf_probe_read_user(event.str, sizeof(event.str), source);
    events.perf_submit(ctx, &event, sizeof(event));

    event.type = EVENT_MOUNT_TARGET;
    __builtin_memset(event.str, 0, sizeof(event.str));
    bpf_probe_read_user(event.str, sizeof(event.str), target);
    events.perf_submit(ctx, &event, sizeof(event));

    event.type = EVENT_MOUNT_TYPE;
    __builtin_memset(event.str, 0, sizeof(event.str));
    bpf_probe_read_user(event.str, sizeof(event.str), type);
    events.perf_submit(ctx, &event, sizeof(event));

    event.type = EVENT_MOUNT_DATA;
    __builtin_memset(event.str, 0, sizeof(event.str));
    bpf_probe_read_user(event.str, sizeof(event.str), data);
    events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}

int syscall__fsopen(struct pt_regs *ctx, char __user *fs_name,
                    unsigned long flags)
{
    struct data_t event = {};
    struct task_struct *task;
    struct nsproxy *nsproxy;
    struct mnt_namespace *mnt_ns;

    if (container_should_be_filtered()) {
        return 0;
    }

    event.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    event.tgid = bpf_get_current_pid_tgid() >> 32;

    event.type = EVENT_FSOPEN;
    bpf_get_current_comm(event.enter.comm, sizeof(event.enter.comm));
    event.enter.flags = flags;
    task = (struct task_struct *)bpf_get_current_task();
    event.enter.ppid = task->real_parent->tgid;
    bpf_probe_read_kernel_str(&event.enter.pcomm, TASK_COMM_LEN, task->real_parent->comm);
    nsproxy = task->nsproxy;
    mnt_ns = nsproxy->mnt_ns;
    event.enter.mnt_ns = mnt_ns->ns.inum;
    events.perf_submit(ctx, &event, sizeof(event));

    event.type = EVENT_FSOPEN_FS_NAME;
    __builtin_memset(event.str, 0, sizeof(event.str));
    bpf_probe_read_user(event.str, sizeof(event.str), fs_name);
    events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}

int syscall__fsmount(struct pt_regs *ctx, unsigned int fs_fd,
                     unsigned int flags, unsigned int attr_flags)
{
    struct data_t event = {};
    struct task_struct *task;
    struct nsproxy *nsproxy;
    struct mnt_namespace *mnt_ns;

    if (container_should_be_filtered()) {
        return 0;
    }

    event.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    event.tgid = bpf_get_current_pid_tgid() >> 32;

    event.type = EVENT_FSMOUNT;
    bpf_get_current_comm(event.enter.comm, sizeof(event.enter.comm));
    event.enter.flags = flags;
    task = (struct task_struct *)bpf_get_current_task();
    event.enter.ppid = task->real_parent->tgid;
    bpf_probe_read_kernel_str(&event.enter.pcomm, TASK_COMM_LEN, task->real_parent->comm);
    nsproxy = task->nsproxy;
    mnt_ns = nsproxy->mnt_ns;
    event.enter.mnt_ns = mnt_ns->ns.inum;
    events.perf_submit(ctx, &event, sizeof(event));

    event.type = EVENT_FSMOUNT_PARAMS;
    event.fsmount.fs_fd = fs_fd;
    event.fsmount.attr_flags = attr_flags;
    events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}

int syscall__fsconfig(struct pt_regs *ctx, int fd, unsigned int cmd,
                      char *key, char *value, int aux)
{
    struct data_t event = {};
    struct task_struct *task;
    struct nsproxy *nsproxy;
    struct mnt_namespace *mnt_ns;

    if (container_should_be_filtered()) {
        return 0;
    }

    event.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    event.tgid = bpf_get_current_pid_tgid() >> 32;

    event.type = EVENT_FSCONFIG;
    bpf_get_current_comm(event.enter.comm, sizeof(event.enter.comm));
    task = (struct task_struct *)bpf_get_current_task();
    event.enter.ppid = task->real_parent->tgid;
    bpf_probe_read_kernel_str(&event.enter.pcomm, TASK_COMM_LEN, task->real_parent->comm);
    nsproxy = task->nsproxy;
    mnt_ns = nsproxy->mnt_ns;
    event.enter.mnt_ns = mnt_ns->ns.inum;
    events.perf_submit(ctx, &event, sizeof(event));

    event.type = EVENT_FSCONFIG_PARAMS;
    event.fsconfig.fd = fd;
    event.fsconfig.cmd = cmd;
    /*
     * FIXME: fsconfig.key, fsconfig.value and fsconfig.aux can be used in
     * different combinations, and perhaps we should distinguish between them.
     */
    __builtin_memset(event.fsconfig.key, 0, sizeof(event.fsconfig.key));
    bpf_probe_read_user(event.fsconfig.key, sizeof(event.fsconfig.key), key);
    __builtin_memset(event.fsconfig.value, 0, sizeof(event.fsconfig.value));
    bpf_probe_read_user(event.fsconfig.value, sizeof(event.fsconfig.value), value);
    event.fsconfig.aux = aux;
    events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}

int syscall__move_mount(struct pt_regs *ctx,
                        int from_dfd, char *from_pathname,
                        int to_dfd, char *to_pathname,
                        unsigned int flags)
{
    struct data_t event = {};
    struct task_struct *task;
    struct nsproxy *nsproxy;
    struct mnt_namespace *mnt_ns;

    if (container_should_be_filtered()) {
        return 0;
    }

    event.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    event.tgid = bpf_get_current_pid_tgid() >> 32;

    event.type = EVENT_MOVE_MOUNT;
    bpf_get_current_comm(event.enter.comm, sizeof(event.enter.comm));
    event.enter.flags = flags;
    task = (struct task_struct *)bpf_get_current_task();
    event.enter.ppid = task->real_parent->tgid;
    bpf_probe_read_kernel_str(&event.enter.pcomm, TASK_COMM_LEN, task->real_parent->comm);
    nsproxy = task->nsproxy;
    mnt_ns = nsproxy->mnt_ns;
    event.enter.mnt_ns = mnt_ns->ns.inum;
    events.perf_submit(ctx, &event, sizeof(event));

    event.type = EVENT_MOVE_MOUNT_PARAMS;
    event.move_mount.from_dfd = from_dfd;
    __builtin_memset(event.move_mount.from_pathname, 0,
                     sizeof(event.move_mount.from_pathname));
    bpf_probe_read_user(event.move_mount.from_pathname,
                        sizeof(event.move_mount.from_pathname), from_pathname);
    event.move_mount.to_dfd = to_dfd;
    __builtin_memset(event.move_mount.to_pathname, 0,
                     sizeof(event.move_mount.to_pathname));
    bpf_probe_read_user(event.move_mount.to_pathname,
                        sizeof(event.move_mount.to_pathname), to_pathname);
    event.move_mount.flags = flags;
    events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}

static int __do_ret_sys(struct pt_regs *ctx, int ret)
{
    struct data_t event = {};

    event.type = ret;
    event.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    event.tgid = bpf_get_current_pid_tgid() >> 32;
    event.retval = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}

int do_ret_sys_mount(struct pt_regs *ctx)
{
    return __do_ret_sys(ctx, EVENT_MOUNT_RET);
}

int do_ret_sys_fsopen(struct pt_regs *ctx)
{
    return __do_ret_sys(ctx, EVENT_FSOPEN_RET);
}

int do_ret_sys_fsmount(struct pt_regs *ctx)
{
    return __do_ret_sys(ctx, EVENT_FSMOUNT_RET);
}

int do_ret_sys_fsconfig(struct pt_regs *ctx)
{
    return __do_ret_sys(ctx, EVENT_FSCONFIG_RET);
}

int do_ret_sys_move_mount(struct pt_regs *ctx)
{
    return __do_ret_sys(ctx, EVENT_MOVE_MOUNT_RET);
}

int syscall__umount(struct pt_regs *ctx, char __user *target, int flags)
{
    struct data_t event = {};
    struct task_struct *task;
    struct nsproxy *nsproxy;
    struct mnt_namespace *mnt_ns;

    if (container_should_be_filtered()) {
        return 0;
    }

    event.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    event.tgid = bpf_get_current_pid_tgid() >> 32;

    event.type = EVENT_UMOUNT;
    bpf_get_current_comm(event.enter.comm, sizeof(event.enter.comm));
    event.enter.flags = flags;
    task = (struct task_struct *)bpf_get_current_task();
    event.enter.ppid = task->real_parent->tgid;
    bpf_probe_read_kernel_str(&event.enter.pcomm, TASK_COMM_LEN, task->real_parent->comm);
    nsproxy = task->nsproxy;
    mnt_ns = nsproxy->mnt_ns;
    event.enter.mnt_ns = mnt_ns->ns.inum;
    events.perf_submit(ctx, &event, sizeof(event));

    event.type = EVENT_UMOUNT_TARGET;
    __builtin_memset(event.str, 0, sizeof(event.str));
    bpf_probe_read_user(event.str, sizeof(event.str), target);
    events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}

int do_ret_sys_umount(struct pt_regs *ctx)
{
    return __do_ret_sys(ctx, EVENT_UMOUNT_RET);
}
"""

# sys/mount.h
MS_MGC_VAL = 0xc0ed0000
MS_MGC_MSK = 0xffff0000
MOUNT_FLAGS = [
    ('MS_RDONLY', 1),
    ('MS_NOSUID', 2),
    ('MS_NODEV', 4),
    ('MS_NOEXEC', 8),
    ('MS_SYNCHRONOUS', 16),
    ('MS_REMOUNT', 32),
    ('MS_MANDLOCK', 64),
    ('MS_DIRSYNC', 128),
    ('MS_NOATIME', 1024),
    ('MS_NODIRATIME', 2048),
    ('MS_BIND', 4096),
    ('MS_MOVE', 8192),
    ('MS_REC', 16384),
    ('MS_SILENT', 32768),
    ('MS_POSIXACL', 1 << 16),
    ('MS_UNBINDABLE', 1 << 17),
    ('MS_PRIVATE', 1 << 18),
    ('MS_SLAVE', 1 << 19),
    ('MS_SHARED', 1 << 20),
    ('MS_RELATIME', 1 << 21),
    ('MS_KERNMOUNT', 1 << 22),
    ('MS_I_VERSION', 1 << 23),
    ('MS_STRICTATIME', 1 << 24),
    ('MS_LAZYTIME', 1 << 25),
    ('MS_ACTIVE', 1 << 30),
    ('MS_NOUSER', 1 << 31),
]

FSMOUNT_FLAGS = [
    ('FSMOUNT_CLOEXEC', 0x00000001),
]

MOUNT_ATTR_FLAGS = [
    ('MOUNT_ATTR_RDONLY', 0x00000001),
    ('MOUNT_ATTR_NOSUID', 0x00000002),
    ('MOUNT_ATTR_NODEV', 0x00000004),
    ('MOUNT_ATTR_NOEXEC', 0x00000008),
    ('MOUNT_ATTR__ATIME', 0x00000070),
    ('MOUNT_ATTR_RELATIME', 0x00000000),
    ('MOUNT_ATTR_NOATIME', 0x00000010),
    ('MOUNT_ATTR_STRICTATIME', 0x00000020),
    ('MOUNT_ATTR_NODIRATIME', 0x00000080),
    ('MOUNT_ATTR_IDMAP', 0x00100000),
    ('MOUNT_ATTR_NOSYMFOLLOW', 0x00200000),
]

FSCONFIG_CMD = [
    ('FSCONFIG_SET_FLAG', 0),
    ('FSCONFIG_SET_STRING', 1),
    ('FSCONFIG_SET_BINARY', 2),
    ('FSCONFIG_SET_PATH', 3),
    ('FSCONFIG_SET_PATH_EMPTY', 4),
    ('FSCONFIG_SET_FD', 5),
    ('FSCONFIG_CMD_CREATE', 6),
    ('FSCONFIG_CMD_RECONFIGURE', 7),
    ('FSCONFIG_CMD_CREATE_EXCL', 8),
]

MOVE_MOUNT_FLAGS = [
    ('MOVE_MOUNT_F_SYMLINKS', 0x00000001),
    ('MOVE_MOUNT_F_AUTOMOUNTS', 0x00000002),
    ('MOVE_MOUNT_F_EMPTY_PATH', 0x00000004),
    ('MOVE_MOUNT_T_SYMLINKS', 0x00000010),
    ('MOVE_MOUNT_T_AUTOMOUNTS', 0x00000020),
    ('MOVE_MOUNT_T_EMPTY_PATH', 0x00000040),
    ('MOVE_MOUNT_SET_GROUP', 0x00000100),
    ('MOVE_MOUNT_BENEATH', 0x00000200),
]

UMOUNT_FLAGS = [
    ('MNT_FORCE', 1),
    ('MNT_DETACH', 2),
    ('MNT_EXPIRE', 4),
    ('UMOUNT_NOFOLLOW', 8),
]


TASK_COMM_LEN = 16  # linux/sched.h
MAX_STR_LEN = 412

# linux/fcntl.h
AT_FDCWD = -100

class EventType(object):
    EVENT_MOUNT = 0
    EVENT_MOUNT_SOURCE = 1
    EVENT_MOUNT_TARGET = 2
    EVENT_MOUNT_TYPE = 3
    EVENT_MOUNT_DATA = 4
    EVENT_MOUNT_RET = 5
    EVENT_FSOPEN = 6
    EVENT_FSOPEN_FS_NAME = 7
    EVENT_FSOPEN_RET = 8
    EVENT_FSMOUNT = 9
    EVENT_FSMOUNT_PARAMS = 10
    EVENT_FSMOUNT_RET = 11
    EVENT_FSCONFIG = 12
    EVENT_FSCONFIG_PARAMS = 13
    EVENT_FSCONFIG_RET = 14
    EVENT_MOVE_MOUNT = 15
    EVENT_MOVE_MOUNT_PARAMS = 16
    EVENT_MOVE_MOUNT_RET = 17
    EVENT_UMOUNT = 18
    EVENT_UMOUNT_TARGET = 19
    EVENT_UMOUNT_RET = 20


class EnterData(ctypes.Structure):
    _fields_ = [
        ('mnt_ns', ctypes.c_uint),
        ('comm', ctypes.c_char * TASK_COMM_LEN),
        ('pcomm', ctypes.c_char * TASK_COMM_LEN),
        ('ppid', ctypes.c_uint),
        ('flags', ctypes.c_ulong),
    ]

class FsmountParam(ctypes.Structure):
    _fields_ = [
        ('fs_fd', ctypes.c_int),
        ('attr_flags', ctypes.c_uint),
    ]

class FsconfigParam(ctypes.Structure):
    _fields_ = [
        ('fd', ctypes.c_int),
        ('cmd', ctypes.c_uint),
        ('key', ctypes.c_char * 32),
        ('value', ctypes.c_char * 32),
        ('aux', ctypes.c_uint),
    ]

class MoveMountParam(ctypes.Structure):
    _fields_ = [
        ('from_dfd', ctypes.c_int),
        ('from_pathname', ctypes.c_char * 128),
        ('to_dfd', ctypes.c_int),
        ('to_pathname', ctypes.c_char * 128),
        ('flags', ctypes.c_uint),
    ]

class DataUnion(ctypes.Union):
    _fields_ = [
        ('enter', EnterData),
        ('str', ctypes.c_char * MAX_STR_LEN),
        ('fsmount', FsmountParam),
        ('fsconfig', FsconfigParam),
        ('move_mount', MoveMountParam),
        ('retval', ctypes.c_int),
    ]


class Event(ctypes.Structure):
    _fields_ = [
        ('type', ctypes.c_uint),
        ('pid', ctypes.c_uint),
        ('tgid', ctypes.c_uint),
        ('union', DataUnion),
    ]


def _decode_flags(flags, flag_list):
    str_flags = []
    for flag, bit in flag_list:
        if flags & bit:
            str_flags.append(flag)
        flags &= ~bit
    if flags or not str_flags:
        str_flags.append('0x{:x}'.format(flags))
    return str_flags

def _decode_cmd(cmd, cmd_list):
    for str_cmd, cmd_val in cmd_list:
        if cmd == cmd_val:
            return str_cmd
    return '0x{:x}'.format(cmd)


def decode_flags(flags, flag_list):
    return '|'.join(_decode_flags(flags, flag_list))


def decode_mount_flags(flags):
    str_flags = []
    if flags & MS_MGC_MSK == MS_MGC_VAL:
        flags &= ~MS_MGC_MSK
        str_flags.append('MS_MGC_VAL')
    str_flags.extend(_decode_flags(flags, MOUNT_FLAGS))
    return '|'.join(str_flags)

def decode_fsmount_flags(flags):
    str_flags = []
    str_flags.extend(_decode_flags(flags, FSMOUNT_FLAGS))
    return '|'.join(str_flags)

def decode_mount_attr_flags(flags):
    str_flags = []
    str_flags.extend(_decode_flags(flags, MOUNT_ATTR_FLAGS))
    return '|'.join(str_flags)

def decode_fsconfig_cmd(cmd):
    return _decode_cmd(cmd, FSCONFIG_CMD)

def decode_move_mount_flags(flags):
    str_flags = []
    str_flags.extend(_decode_flags(flags, MOVE_MOUNT_FLAGS))
    return '|'.join(str_flags)

def decode_umount_flags(flags):
    return decode_flags(flags, UMOUNT_FLAGS)

def decode_special_fd(fd):
    if fd == AT_FDCWD:
        return 'AT_FDCWD'
    return '{:d}'.format(fd)

def decode_errno(retval):
    try:
        return '-' + errno.errorcode[-retval]
    except KeyError:
        return str(retval)


_escape_chars = {
    ord('\a'): '\\a',
    ord('\b'): '\\b',
    ord('\t'): '\\t',
    ord('\n'): '\\n',
    ord('\v'): '\\v',
    ord('\f'): '\\f',
    ord('\r'): '\\r',
    ord('"'): '\\"',
    ord('\\'): '\\\\',
}


def escape_character(c):
    try:
        return _escape_chars[c]
    except KeyError:
        if 0x20 <= c <= 0x7e:
            return chr(c)
        else:
            return '\\x{:02x}'.format(c)


if sys.version_info.major < 3:
    def decode_mount_string(s):
        return '"{}"'.format(''.join(escape_character(ord(c)) for c in s))
else:
    def decode_mount_string(s):
        return '"{}"'.format(''.join(escape_character(c) for c in s))


def print_event(mounts, umounts, parent, cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents

    try:
        if (event.type == EventType.EVENT_MOUNT or
            event.type == EventType.EVENT_FSOPEN or
            event.type == EventType.EVENT_FSMOUNT or
            event.type == EventType.EVENT_FSCONFIG or
            event.type == EventType.EVENT_MOVE_MOUNT):
            mounts[event.pid] = {
                'pid': event.pid,
                'tgid': event.tgid,
                'mnt_ns': event.union.enter.mnt_ns,
                'comm': event.union.enter.comm,
                'flags': event.union.enter.flags,
                'ppid': event.union.enter.ppid,
                'pcomm': event.union.enter.pcomm,
            }
        elif event.type == EventType.EVENT_MOUNT_SOURCE:
            mounts[event.pid]['source'] = event.union.str
        elif event.type == EventType.EVENT_MOUNT_TARGET:
            mounts[event.pid]['target'] = event.union.str
        elif event.type == EventType.EVENT_MOUNT_TYPE:
            mounts[event.pid]['type'] = event.union.str
        elif event.type == EventType.EVENT_MOUNT_DATA:
            # XXX: data is not always a NUL-terminated string
            mounts[event.pid]['data'] = event.union.str
        elif event.type == EventType.EVENT_FSOPEN_FS_NAME:
            mounts[event.pid]['fs_name'] = event.union.str
        elif event.type == EventType.EVENT_FSMOUNT_PARAMS:
            mounts[event.pid]['fs_fd'] = event.union.fsmount.fs_fd
            mounts[event.pid]['attr_flags'] = event.union.fsmount.attr_flags
        elif event.type == EventType.EVENT_FSCONFIG_PARAMS:
            mounts[event.pid]['fd'] = event.union.fsconfig.fd
            mounts[event.pid]['cmd'] = event.union.fsconfig.cmd
            mounts[event.pid]['key'] = event.union.fsconfig.key
            mounts[event.pid]['value'] = event.union.fsconfig.value
            mounts[event.pid]['aux'] = event.union.fsconfig.aux
        elif event.type == EventType.EVENT_MOVE_MOUNT_PARAMS:
            mounts[event.pid]['from_dfd'] = event.union.move_mount.from_dfd
            mounts[event.pid]['from_pathname'] = event.union.move_mount.from_pathname
            mounts[event.pid]['to_dfd'] = event.union.move_mount.to_dfd
            mounts[event.pid]['to_pathname'] = event.union.move_mount.to_pathname
            mounts[event.pid]['flags'] = event.union.move_mount.flags
        elif event.type == EventType.EVENT_UMOUNT:
            umounts[event.pid] = {
                'pid': event.pid,
                'tgid': event.tgid,
                'mnt_ns': event.union.enter.mnt_ns,
                'comm': event.union.enter.comm,
                'flags': event.union.enter.flags,
                'ppid': event.union.enter.ppid,
                'pcomm': event.union.enter.pcomm,
            }
        elif event.type == EventType.EVENT_UMOUNT_TARGET:
            umounts[event.pid]['target'] = event.union.str
        elif (event.type == EventType.EVENT_MOUNT_RET or
              event.type == EventType.EVENT_UMOUNT_RET or
              event.type == EventType.EVENT_FSOPEN_RET or
              event.type == EventType.EVENT_FSMOUNT_RET or
              event.type == EventType.EVENT_FSCONFIG_RET or
              event.type == EventType.EVENT_MOVE_MOUNT_RET):
            if event.type == EventType.EVENT_MOUNT_RET:
                syscall = mounts.pop(event.pid)
                call = ('mount({source}, {target}, {type}, {flags}, {data}) ' +
                        '= {retval}').format(
                    source=decode_mount_string(syscall['source']),
                    target=decode_mount_string(syscall['target']),
                    type=decode_mount_string(syscall['type']),
                    flags=decode_mount_flags(syscall['flags']),
                    data=decode_mount_string(syscall['data']),
                    retval=decode_errno(event.union.retval))
            elif event.type == EventType.EVENT_UMOUNT_RET:
                syscall = umounts.pop(event.pid)
                call = 'umount({target}, {flags}) = {retval}'.format(
                    target=decode_mount_string(syscall['target']),
                    flags=decode_umount_flags(syscall['flags']),
                    retval=decode_errno(event.union.retval))
            elif event.type == EventType.EVENT_FSOPEN_RET:
                syscall = mounts.pop(event.pid)
                call = ('fsopen({fs_name}, {flags}) ' +
                        '= {retval}').format(
                    fs_name=decode_mount_string(syscall['fs_name']),
                    flags=decode_mount_flags(syscall['flags']),
                    retval=decode_errno(event.union.retval))
            elif event.type == EventType.EVENT_FSMOUNT_RET:
                syscall = mounts.pop(event.pid)
                call = ('fsmount({fs_fd}, {flags}, {attr_flags}) ' +
                        '= {retval}').format(
                    fs_fd=syscall['fs_fd'],
                    flags=decode_fsmount_flags(syscall['flags']),
                    attr_flags=decode_mount_attr_flags(syscall['attr_flags']),
                    retval=decode_errno(event.union.retval))
            elif event.type == EventType.EVENT_FSCONFIG_RET:
                syscall = mounts.pop(event.pid)
                call = ('fsconfig({fd}, {cmd}, {key}, {value}, {aux}) ' +
                        '= {retval}').format(
                    fd=syscall['fd'],
                    cmd=decode_fsconfig_cmd(syscall['cmd']),
                    key=decode_mount_string(syscall['key']),
                    value=decode_mount_string(syscall['value']),
                    aux=syscall['aux'],
                    retval=decode_errno(event.union.retval))
            elif event.type == EventType.EVENT_MOVE_MOUNT_RET:
                syscall = mounts.pop(event.pid)
                call = ('move_mount({from_dfd}, {from_pathname}, {to_dfd}, {to_pathname}, {flags}) ' +
                        '= {retval}').format(
                    from_dfd=syscall['from_dfd'],
                    from_pathname=decode_mount_string(syscall['from_pathname']),
                    # maye to_dfd == AT_FDCWD
                    to_dfd=decode_special_fd(syscall['to_dfd']),
                    to_pathname=decode_mount_string(syscall['to_pathname']),
                    flags=decode_move_mount_flags(syscall['flags']),
                    retval=decode_errno(event.union.retval))
            if parent:
                print('{:16} {:<7} {:<7} {:16} {:<7} {:<11} {}'.format(
                    syscall['comm'].decode('utf-8', 'replace'), syscall['tgid'],
                    syscall['pid'], syscall['pcomm'].decode('utf-8', 'replace'),
                    syscall['ppid'], syscall['mnt_ns'], call))
            else:
                print('{:16} {:<7} {:<7} {:<11} {}'.format(
                    syscall['comm'].decode('utf-8', 'replace'), syscall['tgid'],
                    syscall['pid'], syscall['mnt_ns'], call))
        sys.stdout.flush()
    except KeyError:
        # This might happen if we lost an event.
        pass


def main():
    parser = argparse.ArgumentParser(
        description='trace mount() and umount() syscalls'
    )
    parser.add_argument("--ebpf", action="store_true",
        help=argparse.SUPPRESS)
    parser.add_argument("-P", "--parent_process", action="store_true",
        help="also snoop the parent process")
    parser.add_argument("--cgroupmap",
        help="trace cgroups in this BPF map only")
    parser.add_argument("--mntnsmap",
        help="trace mount namespaces in this BPF map only")
    args = parser.parse_args()

    mounts = {}
    umounts = {}
    global bpf_text
    bpf_text = filter_by_containers(args) + bpf_text
    if args.ebpf:
        print(bpf_text)
        exit()

    b = bcc.BPF(text=bpf_text)

    mount_fnname = b.get_syscall_fnname("mount")
    # fsopne(2) syscall add since kernel commit 24dcb3d90a1f ("vfs: syscall:
    # Add fsopen() to prepare for superblock creation") v5.1-rc1-5-g24dcb3d90a1f
    fsopen_fnname = b.get_syscall_fnname("fsopen")
    # fsconfig(2) syscall add since kernel commit ecdab150fddb ("vfs: syscall:
    # Add fsconfig() for configuring and managing a context") v5.1-rc1-7-gecdab150fddb
    fsconfig_fnname = b.get_syscall_fnname("fsconfig")
    # fsmount(2) syscall add since kernel commit 93766fbd2696 ("vfs: syscall:
    # Add fsmount() to create a mount for a superblock") v5.1-rc1-8-g93766fbd2696
    fsmount_fnname = b.get_syscall_fnname("fsmount")
    # move_mount(2) syscall add since kernel commit 2db154b3ea8e ("vfs: syscall:
    # Add move_mount(2) to move mounts around"), v5.1-rc1-2-g2db154b3ea8e
    move_mount_fnname = b.get_syscall_fnname("move_mount")
    umount_fnname = b.get_syscall_fnname("umount")

    if b.ksymname(fsopen_fnname) == -1:
        fsopen_fnname = None
    if b.ksymname(fsconfig_fnname) == -1:
        fsconfig_fnname = None
    if b.ksymname(fsmount_fnname) == -1:
        fsmount_fnname = None
    if b.ksymname(move_mount_fnname) == -1:
        move_mount_fnname = None

    b.attach_kprobe(event=mount_fnname, fn_name="syscall__mount")
    b.attach_kretprobe(event=mount_fnname, fn_name="do_ret_sys_mount")

    if fsopen_fnname:
        b.attach_kprobe(event=fsopen_fnname, fn_name="syscall__fsopen")
        b.attach_kretprobe(event=fsopen_fnname, fn_name="do_ret_sys_fsopen")
    if fsmount_fnname:
        b.attach_kprobe(event=fsmount_fnname, fn_name="syscall__fsmount")
        b.attach_kretprobe(event=fsmount_fnname, fn_name="do_ret_sys_fsmount")
    if fsconfig_fnname:
        b.attach_kprobe(event=fsconfig_fnname, fn_name="syscall__fsconfig")
        b.attach_kretprobe(event=fsconfig_fnname, fn_name="do_ret_sys_fsconfig")
    if move_mount_fnname:
        b.attach_kprobe(event=move_mount_fnname, fn_name="syscall__move_mount")
        b.attach_kretprobe(event=move_mount_fnname, fn_name="do_ret_sys_move_mount")

    b.attach_kprobe(event=umount_fnname, fn_name="syscall__umount")
    b.attach_kretprobe(event=umount_fnname, fn_name="do_ret_sys_umount")

    b['events'].open_perf_buffer(
        functools.partial(print_event, mounts, umounts, args.parent_process))

    if args.parent_process:
        print('{:16} {:<7} {:<7} {:16} {:<7} {:<11} {}'.format(
              'COMM', 'PID', 'TID', 'PCOMM', 'PPID', 'MNT_NS', 'CALL'))
    else:
        print('{:16} {:<7} {:<7} {:<11} {}'.format(
            'COMM', 'PID', 'TID', 'MNT_NS', 'CALL'))

    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()



if __name__ == '__main__':
    main()

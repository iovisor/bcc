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

from __future__ import print_function
import argparse
import bcc
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
 */
struct mnt_namespace {
    atomic_t count;
    struct ns_common ns;
};

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
    EVENT_UMOUNT,
    EVENT_UMOUNT_TARGET,
    EVENT_UMOUNT_RET,
};

struct data_t {
    enum event_type type;
    pid_t pid, tgid;
    union {
        /* EVENT_MOUNT, EVENT_UMOUNT */
        struct {
            /* current->nsproxy->mnt_ns->ns.inum */
            unsigned int mnt_ns;
            char comm[TASK_COMM_LEN];
            unsigned long flags;
        } enter;
        /*
         * EVENT_MOUNT_SOURCE, EVENT_MOUNT_TARGET, EVENT_MOUNT_TYPE,
         * EVENT_MOUNT_DATA, EVENT_UMOUNT_TARGET
         */
        char str[MAX_STR_LEN];
        /* EVENT_MOUNT_RET, EVENT_UMOUNT_RET */
        int retval;
    };
};

BPF_PERF_OUTPUT(events);

int syscall__mount(struct pt_regs *ctx, char __user *source,
                      char __user *target, char __user *type,
                      unsigned long flags)
{
    /* sys_mount takes too many arguments */
    char __user *data = (char __user *)PT_REGS_PARM5(ctx);
    struct data_t event = {};
    struct task_struct *task;
    struct nsproxy *nsproxy;
    struct mnt_namespace *mnt_ns;

    event.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    event.tgid = bpf_get_current_pid_tgid() >> 32;

    event.type = EVENT_MOUNT;
    bpf_get_current_comm(event.enter.comm, sizeof(event.enter.comm));
    event.enter.flags = flags;
    task = (struct task_struct *)bpf_get_current_task();
    nsproxy = task->nsproxy;
    mnt_ns = nsproxy->mnt_ns;
    event.enter.mnt_ns = mnt_ns->ns.inum;
    events.perf_submit(ctx, &event, sizeof(event));

    event.type = EVENT_MOUNT_SOURCE;
    memset(event.str, 0, sizeof(event.str));
    bpf_probe_read(event.str, sizeof(event.str), source);
    events.perf_submit(ctx, &event, sizeof(event));

    event.type = EVENT_MOUNT_TARGET;
    memset(event.str, 0, sizeof(event.str));
    bpf_probe_read(event.str, sizeof(event.str), target);
    events.perf_submit(ctx, &event, sizeof(event));

    event.type = EVENT_MOUNT_TYPE;
    memset(event.str, 0, sizeof(event.str));
    bpf_probe_read(event.str, sizeof(event.str), type);
    events.perf_submit(ctx, &event, sizeof(event));

    event.type = EVENT_MOUNT_DATA;
    memset(event.str, 0, sizeof(event.str));
    bpf_probe_read(event.str, sizeof(event.str), data);
    events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}

int do_ret_sys_mount(struct pt_regs *ctx)
{
    struct data_t event = {};

    event.type = EVENT_MOUNT_RET;
    event.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    event.tgid = bpf_get_current_pid_tgid() >> 32;
    event.retval = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}

int syscall__umount(struct pt_regs *ctx, char __user *target, int flags)
{
    struct data_t event = {};
    struct task_struct *task;
    struct nsproxy *nsproxy;
    struct mnt_namespace *mnt_ns;

    event.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    event.tgid = bpf_get_current_pid_tgid() >> 32;

    event.type = EVENT_UMOUNT;
    bpf_get_current_comm(event.enter.comm, sizeof(event.enter.comm));
    event.enter.flags = flags;
    task = (struct task_struct *)bpf_get_current_task();
    nsproxy = task->nsproxy;
    mnt_ns = nsproxy->mnt_ns;
    event.enter.mnt_ns = mnt_ns->ns.inum;
    events.perf_submit(ctx, &event, sizeof(event));

    event.type = EVENT_UMOUNT_TARGET;
    memset(event.str, 0, sizeof(event.str));
    bpf_probe_read(event.str, sizeof(event.str), target);
    events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}

int do_ret_sys_umount(struct pt_regs *ctx)
{
    struct data_t event = {};

    event.type = EVENT_UMOUNT_RET;
    event.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    event.tgid = bpf_get_current_pid_tgid() >> 32;
    event.retval = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &event, sizeof(event));

    return 0;
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
UMOUNT_FLAGS = [
    ('MNT_FORCE', 1),
    ('MNT_DETACH', 2),
    ('MNT_EXPIRE', 4),
    ('UMOUNT_NOFOLLOW', 8),
]


TASK_COMM_LEN = 16  # linux/sched.h
MAX_STR_LEN = 412


class EventType(object):
    EVENT_MOUNT = 0
    EVENT_MOUNT_SOURCE = 1
    EVENT_MOUNT_TARGET = 2
    EVENT_MOUNT_TYPE = 3
    EVENT_MOUNT_DATA = 4
    EVENT_MOUNT_RET = 5
    EVENT_UMOUNT = 6
    EVENT_UMOUNT_TARGET = 7
    EVENT_UMOUNT_RET = 8


class EnterData(ctypes.Structure):
    _fields_ = [
        ('mnt_ns', ctypes.c_uint),
        ('comm', ctypes.c_char * TASK_COMM_LEN),
        ('flags', ctypes.c_ulong),
    ]


class DataUnion(ctypes.Union):
    _fields_ = [
        ('enter', EnterData),
        ('str', ctypes.c_char * MAX_STR_LEN),
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


def decode_flags(flags, flag_list):
    return '|'.join(_decode_flags(flags, flag_list))


def decode_mount_flags(flags):
    str_flags = []
    if flags & MS_MGC_MSK == MS_MGC_VAL:
        flags &= ~MS_MGC_MSK
        str_flags.append('MS_MGC_VAL')
    str_flags.extend(_decode_flags(flags, MOUNT_FLAGS))
    return '|'.join(str_flags)


def decode_umount_flags(flags):
    return decode_flags(flags, UMOUNT_FLAGS)


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


def print_event(mounts, umounts, cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents

    try:
        if event.type == EventType.EVENT_MOUNT:
            mounts[event.pid] = {
                'pid': event.pid,
                'tgid': event.tgid,
                'mnt_ns': event.union.enter.mnt_ns,
                'comm': event.union.enter.comm,
                'flags': event.union.enter.flags,
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
        elif event.type == EventType.EVENT_UMOUNT:
            umounts[event.pid] = {
                'pid': event.pid,
                'tgid': event.tgid,
                'mnt_ns': event.union.enter.mnt_ns,
                'comm': event.union.enter.comm,
                'flags': event.union.enter.flags,
            }
        elif event.type == EventType.EVENT_UMOUNT_TARGET:
            umounts[event.pid]['target'] = event.union.str
        elif (event.type == EventType.EVENT_MOUNT_RET or
              event.type == EventType.EVENT_UMOUNT_RET):
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
            else:
                syscall = umounts.pop(event.pid)
                call = 'umount({target}, {flags}) = {retval}'.format(
                    target=decode_mount_string(syscall['target']),
                    flags=decode_umount_flags(syscall['flags']),
                    retval=decode_errno(event.union.retval))
            print('{:16} {:<7} {:<7} {:<11} {}'.format(
                syscall['comm'].decode('utf-8', 'replace'), syscall['tgid'],
                syscall['pid'], syscall['mnt_ns'], call))
    except KeyError:
        # This might happen if we lost an event.
        pass


def main():
    parser = argparse.ArgumentParser(
        description='trace mount() and umount() syscalls'
    )
    parser.add_argument("--ebpf", action="store_true",
        help=argparse.SUPPRESS)
    args = parser.parse_args()

    mounts = {}
    umounts = {}
    if args.ebpf:
        print(bpf_text)
        exit()
    b = bcc.BPF(text=bpf_text)
    mount_fnname = b.get_syscall_fnname("mount")
    b.attach_kprobe(event=mount_fnname, fn_name="syscall__mount")
    b.attach_kretprobe(event=mount_fnname, fn_name="do_ret_sys_mount")
    umount_fnname = b.get_syscall_fnname("umount")
    b.attach_kprobe(event=umount_fnname, fn_name="syscall__umount")
    b.attach_kretprobe(event=umount_fnname, fn_name="do_ret_sys_umount")
    b['events'].open_perf_buffer(
        functools.partial(print_event, mounts, umounts))
    print('{:16} {:<7} {:<7} {:<11} {}'.format(
        'COMM', 'PID', 'TID', 'MNT_NS', 'CALL'))
    while True:
        b.perf_buffer_poll()


if __name__ == '__main__':
    main()

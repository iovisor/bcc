#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# statsnoop Trace stat() syscalls.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: statsnoop [-h] [-t] [-x] [-p PID]
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 08-Feb-2016   Brendan Gregg   Created this.
# 17-Feb-2016   Allan McAleavy  updated for BPF_PERF_OUTPUT
# 29-Nov-2022   Rocky Xing      Added stat() variants.

from __future__ import print_function
from bcc import BPF
import argparse

# arguments
examples = """examples:
    ./statsnoop           # trace all stat() syscalls
    ./statsnoop -t        # include timestamps
    ./statsnoop -s        # include syscall name
    ./statsnoop -x        # only show failed stats
    ./statsnoop -p 181    # only trace PID 181
"""
parser = argparse.ArgumentParser(
    description="Trace stat() syscalls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-t", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-s", "--sysname", action="store_true",
    help="include syscall name on output")
parser.add_argument("-x", "--failed", action="store_true",
    help="only show failed stats")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>

enum sys_type {
    SYS_STAT = 1,
    SYS_STATX,
    SYS_STATFS,
    SYS_NEWSTAT,
    SYS_NEWLSTAT,
    SYS_FSTATAT64,
    SYS_NEWFSTATAT,
};

struct val_t {
    const char *fname;
    enum sys_type type;
};

struct data_t {
    u32 pid;
    u64 ts_ns;
    int ret;
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
    u32 type; /* enum sys_type */
};

BPF_HASH(infotmp, u32, struct val_t);
BPF_PERF_OUTPUT(events);

static int trace_entry(struct pt_regs *ctx, enum sys_type type,
                       const char __user *filename)
{
    struct val_t val = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    FILTER
    val.fname = filename;
    val.type = type;
    infotmp.update(&tid, &val);

    return 0;
};

int syscall__stat_entry(struct pt_regs *ctx, const char __user *filename)
{
    return trace_entry(ctx, SYS_STAT, filename);
}

int syscall__statfs_entry(struct pt_regs *ctx, const char __user *filename)
{
    return trace_entry(ctx, SYS_STATFS, filename);
}

int syscall__newstat_entry(struct pt_regs *ctx, const char __user *filename)
{
    return trace_entry(ctx, SYS_NEWSTAT, filename);
}

int syscall__newlstat_entry(struct pt_regs *ctx, const char __user *filename)
{
    return trace_entry(ctx, SYS_NEWLSTAT, filename);
}

int syscall__statx_entry(struct pt_regs *ctx, int dfd, const char __user *filename)
{
    return trace_entry(ctx, SYS_STATX, filename);
}

int syscall__fstatat64_entry(struct pt_regs *ctx, int dfd, const char __user *filename)
{
    return trace_entry(ctx, SYS_FSTATAT64, filename);
}

int syscall__newfstatat_entry(struct pt_regs *ctx, int dfd, const char __user *filename)
{
    return trace_entry(ctx, SYS_NEWFSTATAT, filename);
}

int trace_return(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    struct val_t *valp;

    valp = infotmp.lookup(&tid);
    if (valp == 0) {
        // missed entry
        return 0;
    }

    struct data_t data = {.pid = pid_tgid >> 32};
    bpf_probe_read_user(&data.fname, sizeof(data.fname), (void *)valp->fname);
    data.type = valp->type;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.ts_ns = bpf_ktime_get_ns();
    data.ret = PT_REGS_RC(ctx);

    events.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&tid);

    return 0;
}
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

# initialize BPF
b = BPF(text=bpf_text)

# for POSIX compliance, all architectures implement these
# system calls but the name of the actual entry point may
# be different for which we must check if the entry points
# actually exist before attaching the probes
def try_attach_syscall_probes(syscall):
    syscall_fnname = b.get_syscall_fnname(syscall)
    if BPF.ksymname(syscall_fnname) != -1:
        b.attach_kprobe(event=syscall_fnname, fn_name="syscall__%s_entry" % syscall)
        b.attach_kretprobe(event=syscall_fnname, fn_name="trace_return")

try_attach_syscall_probes("stat")
try_attach_syscall_probes("statx")
try_attach_syscall_probes("statfs")
try_attach_syscall_probes("newstat")
try_attach_syscall_probes("newlstat")
try_attach_syscall_probes("fstatat64")
try_attach_syscall_probes("newfstatat")

# See enum sys_type.
sys_names = [
    "N/A",
    "stat",
    "statx",
    "statfs",
    "newstat",
    "newlstat",
    "fstatat64",
    "newfstatat",
]

start_ts = 0
prev_ts = 0
delta = 0

# header
if args.timestamp:
    print("%-14s" % ("TIME(s)"), end="")
print("%-7s %-16s %4s %3s" % ("PID", "COMM", "FD", "ERR"), end="")
if args.sysname:
    print(" %-12s" % "SYSCALL", end="")
print(" %s" % "PATH")

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    global start_ts
    global prev_ts
    global delta
    global cont

    # split return value into FD and errno columns
    if event.ret >= 0:
        if args.failed:
            return
        fd_s = event.ret
        err = 0
    else:
        fd_s = -1
        err = - event.ret

    if start_ts == 0:
        start_ts = event.ts_ns

    if args.timestamp:
        print("%-14.9f" % (float(event.ts_ns - start_ts) / 1000000000), end="")

    print("%-7d %-16s %4d %3d" % (event.pid,
        event.comm.decode('utf-8', 'replace'), fd_s, err), end="")

    if args.sysname:
        print(" %-12s" % sys_names[event.type], end="")

    print(" %s" % event.fname.decode('utf-8', 'replace'))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

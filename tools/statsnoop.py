#!/usr/bin/python
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
# 17-Feb-2016   Allan McAleavy updated for BPF_PERF_OUTPUT

from __future__ import print_function
from bcc import BPF
import argparse
import ctypes as ct

# arguments
examples = """examples:
    ./statsnoop           # trace all stat() syscalls
    ./statsnoop -t        # include timestamps
    ./statsnoop -x        # only show failed stats
    ./statsnoop -p 181    # only trace PID 181
"""
parser = argparse.ArgumentParser(
    description="Trace stat() syscalls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-t", "--timestamp", action="store_true",
    help="include timestamp on output")
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

struct val_t {
    const char *fname;
};

struct data_t {
    u32 pid;
    u64 ts_ns;
    int ret;
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
};

BPF_HASH(args_filename, u32, const char *);
BPF_HASH(infotmp, u32, struct val_t);
BPF_PERF_OUTPUT(events);

int syscall__entry(struct pt_regs *ctx, const char __user *filename)
{
    struct val_t val = {};
    u32 pid = bpf_get_current_pid_tgid();

    FILTER
    val.fname = filename;
    infotmp.update(&pid, &val);

    return 0;
};

int trace_return(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct val_t *valp;

    valp = infotmp.lookup(&pid);
    if (valp == 0) {
        // missed entry
        return 0;
    }

    struct data_t data = {.pid = pid};
    bpf_probe_read(&data.fname, sizeof(data.fname), (void *)valp->fname);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.ts_ns = bpf_ktime_get_ns();
    data.ret = PT_REGS_RC(ctx);

    events.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&pid);
    args_filename.delete(&pid);

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
syscall_fnname = b.get_syscall_fnname("stat")
if BPF.ksymname(syscall_fnname) != -1:
    b.attach_kprobe(event=syscall_fnname, fn_name="syscall__entry")
    b.attach_kretprobe(event=syscall_fnname, fn_name="trace_return")

syscall_fnname = b.get_syscall_fnname("statfs")
if BPF.ksymname(syscall_fnname) != -1:
    b.attach_kprobe(event=syscall_fnname, fn_name="syscall__entry")
    b.attach_kretprobe(event=syscall_fnname, fn_name="trace_return")

syscall_fnname = b.get_syscall_fnname("newstat")
if BPF.ksymname(syscall_fnname) != -1:
    b.attach_kprobe(event=syscall_fnname, fn_name="syscall__entry")
    b.attach_kretprobe(event=syscall_fnname, fn_name="trace_return")

TASK_COMM_LEN = 16    # linux/sched.h
NAME_MAX = 255        # linux/limits.h

class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulonglong),
        ("ts_ns", ct.c_ulonglong),
        ("ret", ct.c_int),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("fname", ct.c_char * NAME_MAX)
    ]

start_ts = 0
prev_ts = 0
delta = 0

# header
if args.timestamp:
    print("%-14s" % ("TIME(s)"), end="")
print("%-6s %-16s %4s %3s %s" % ("PID", "COMM", "FD", "ERR", "PATH"))

# process event
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    global start_ts
    global prev_ts
    global delta
    global cont

    # split return value into FD and errno columns
    if event.ret >= 0:
        fd_s = event.ret
        err = 0
    else:
        fd_s = -1
        err = - event.ret

    if start_ts == 0:
        start_ts = event.ts_ns

    if args.timestamp:
        print("%-14.9f" % (float(event.ts_ns - start_ts) / 1000000000), end="")

    print("%-6d %-16s %4d %3d %s" % (event.pid,
        event.comm.decode('utf-8', 'replace'), fd_s, err,
        event.fname.decode('utf-8', 'replace')))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    b.perf_buffer_poll()

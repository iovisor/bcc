#!/usr/bin/python
# Copyright (c) 2025
# Licensed under the Apache License, Version 2.0 (the "License")
#
# chmodsnoop    Trace chmod() syscalls with file paths and mode changes.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: chmodsnoop [-h] [-T] [-x] [-p PID]
#
# This is a simple example of tracing the chmod() syscall to monitor file
# permission changes. It demonstrates how to:
# - Trace system calls using kprobes
# - Extract string arguments from user space
# - Filter by PID
# - Handle syscall errors
#
# This is provided as a basic example of system call tracing.

from __future__ import print_function
from bcc import BPF
import argparse

# arguments
examples = """examples:
    ./chmodsnoop              # trace all chmod() syscalls
    ./chmodsnoop -T           # include timestamps
    ./chmodsnoop -x           # only show failed chmod calls
    ./chmodsnoop -p 181       # only trace PID 181
"""
parser = argparse.ArgumentParser(
    description="Trace chmod() syscalls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-x", "--failed", action="store_true",
    help="only show failed chmod calls")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>

struct val_t {
    const char *fname;
    u32 mode;
};

struct data_t {
    u32 pid;
    u64 ts_ns;
    int ret;
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
    u32 mode;
};

BPF_HASH(infotmp, u32, struct val_t);
BPF_PERF_OUTPUT(events);

int syscall__chmod_entry(struct pt_regs *ctx, const char __user *filename, u32 mode)
{
    struct val_t val = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    u32 pid = pid_tgid >> 32;

    FILTER

    val.fname = filename;
    val.mode = mode;
    infotmp.update(&tid, &val);

    return 0;
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
    data.mode = valp->mode;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.ts_ns = bpf_ktime_get_ns();
    data.ret = PT_REGS_RC(ctx);

    FILTER_FAILED

    events.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&tid);

    return 0;
}
"""

# Build filter strings
if args.pid:
    bpf_text = bpf_text.replace('FILTER',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '')

if args.failed:
    bpf_text = bpf_text.replace('FILTER_FAILED',
        'if (data.ret >= 0) { infotmp.delete(&tid); return 0; }')
else:
    bpf_text = bpf_text.replace('FILTER_FAILED', '')

if args.ebpf:
    print(bpf_text)
    exit()

# initialize BPF
b = BPF(text=bpf_text)

# attach to chmod syscall
# for POSIX compliance, all architectures implement this system call
# but the name of the actual entry point may be different
syscall_fnname = b.get_syscall_fnname("chmod")
try:
    b.attach_kprobe(event=syscall_fnname, fn_name="syscall__chmod_entry")
    b.attach_kretprobe(event=syscall_fnname, fn_name="trace_return")
except Exception as e:
    print("Failed to attach to chmod syscall: %s" % e)
    print("This may require Linux kernel 4.1+ and root privileges.")
    exit(1)

# header
if args.timestamp:
    print("%-18s %-16s %-6s %-10s %s" %
          ("TIME(s)", "COMM", "PID", "MODE", "PATH"))
else:
    print("%-16s %-6s %-10s %s" %
          ("COMM", "PID", "MODE", "PATH"))

start_time = 0

# format mode string
def format_mode(mode):
    """Format mode_t to octal string like '0755'"""
    return oct(mode & 0o7777)[2:].zfill(4)

# process event
def print_event(cpu, data, size):
    global start_time
    event = b["events"].event(data)

    if start_time == 0:
        start_time = event.ts_ns

    mode_str = format_mode(event.mode)

    if args.timestamp:
        ts = (event.ts_ns - start_time) / 1e9
        print("%-18.9f %-16s %-6d %-10s %s" %
              (ts, event.comm.decode('utf-8', 'replace'), event.pid, mode_str, event.fname.decode('utf-8', 'replace')))
    else:
        print("%-16s %-6d %-10s %s" %
              (event.comm.decode('utf-8', 'replace'), event.pid, mode_str, event.fname.decode('utf-8', 'replace')))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
print("Tracing chmod() syscalls... Hit Ctrl-C to end.")

while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()


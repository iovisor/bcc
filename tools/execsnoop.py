#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# execsnoop Trace new processes via exec() syscalls.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: execsnoop [-h] [-t] [-x] [-n NAME]
#
# This currently will print up to a maximum of 19 arguments, plus the process
# name, so 20 fields in total (MAXARG).
#
# This won't catch all new processes: an application may fork() but not exec().
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 07-Feb-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
import argparse
import ctypes as ct
import re
import time
from collections import defaultdict

# arguments
examples = """examples:
    ./execsnoop           # trace all exec() syscalls
    ./execsnoop -x        # include failed exec()s
    ./execsnoop -t        # include timestamps
    ./execsnoop -n main   # only print command lines containing "main"
"""
parser = argparse.ArgumentParser(
    description="Trace exec() syscalls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-t", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-x", "--fails", action="store_true",
    help="include failed exec()s")
parser.add_argument("-n", "--name",
    help="only print commands matching this name (regex), any arg")
args = parser.parse_args()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define MAXARG   20
#define ARGSIZE  128

enum event_type {
    EVENT_ARG,
    EVENT_RET,
};

struct data_t {
    u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    char comm[TASK_COMM_LEN];
    enum event_type type;
    char argv[ARGSIZE];
    int retval;
};

BPF_PERF_OUTPUT(events);

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    bpf_probe_read(data->argv, sizeof(data->argv), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}

int kprobe__sys_execve(struct pt_regs *ctx, struct filename *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    // create data here and pass to submit_arg to save stack space (#555)
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_ARG;

    __submit_arg(ctx, (void *)filename, &data);

    int i = 1;  // skip first arg, as we submitted filename

    // unrolled loop to walk argv[] (MAXARG)
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++; // X
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++;
    if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) goto out; i++; // XX

    // handle truncated argument list
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &data);
out:
    return 0;
}

int kretprobe__sys_execve(struct pt_regs *ctx)
{
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_RET;
    data.retval = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# initialize BPF
b = BPF(text=bpf_text)

# header
if args.timestamp:
    print("%-8s" % ("TIME(s)"), end="")
print("%-16s %-6s %-6s %3s %s" % ("PCOMM", "PID", "PPID", "RET", "ARGS"))

TASK_COMM_LEN = 16      # linux/sched.h
ARGSIZE = 128           # should match #define in C above

class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("type", ct.c_int),
        ("argv", ct.c_char * ARGSIZE),
        ("retval", ct.c_int),
    ]

class EventType(object):
    EVENT_ARG = 0
    EVENT_RET = 1

start_ts = time.time()
argv = defaultdict(list)

# TODO: This is best-effort PPID matching. Short-lived processes may exit
# before we get a chance to read the PPID. This should be replaced with
# fetching PPID via C when available (#364).
def get_ppid(pid):
    try:
        with open("/proc/%d/status" % pid) as status:
            for line in status:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except IOError:
        pass
    return 0

# process event
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents

    skip = False

    if event.type == EventType.EVENT_ARG:
        argv[event.pid].append(event.argv)
    elif event.type == EventType.EVENT_RET:
        if args.fails and event.retval == 0:
            skip = True
        if args.name and not re.search(args.name, event.comm):
            skip = True

        if not skip:
            if args.timestamp:
                print("%-8.3f" % (time.time() - start_ts), end="")
            ppid = get_ppid(event.pid)
            print("%-16s %-6s %-6s %3s %s" % (event.comm.decode(), event.pid,
                    ppid if ppid > 0 else "?", event.retval,
                    b' '.join(argv[event.pid]).decode()))

        del(argv[event.pid])

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    b.kprobe_poll()

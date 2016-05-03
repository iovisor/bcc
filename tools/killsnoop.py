#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# killsnoop Trace signals issued by the kill() syscall.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: killsnoop [-h] [-t] [-x] [-p PID]
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 20-Sep-2015   Brendan Gregg   Created this.
# 19-Feb-2016   Allan McAleavy migrated to BPF_PERF_OUTPUT

from __future__ import print_function
from bcc import BPF
import argparse
import ctypes as ct

# arguments
examples = """examples:
    ./killsnoop           # trace all kill() signals
    ./killsnoop -t        # include timestamps
    ./killsnoop -x        # only show failed kills
    ./killsnoop -p 181    # only trace PID 181
"""
parser = argparse.ArgumentParser(
    description="Trace signals issued by the kill() syscall",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-t", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-x", "--failed", action="store_true",
    help="only show failed opens")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct val_t {
   u64 pid;
   u64 ts;
   int sig;
   int tpid;
   char comm[TASK_COMM_LEN];
};

struct data_t {
   u64 pid;
   u64 tpid;
   int sig;
   int ret;
   u64 ts;
   u64 delta;
   char comm[TASK_COMM_LEN];
};

BPF_HASH(infotmp, u32, struct val_t);
BPF_PERF_OUTPUT(events);

int kprobe__sys_kill(struct pt_regs *ctx, int tpid, int sig)
{
    struct val_t val = {};
    u32 pid = bpf_get_current_pid_tgid();

    FILTER
    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        val.pid = bpf_get_current_pid_tgid();
        val.ts = bpf_ktime_get_ns();
        val.tpid = tpid;
        val.sig = sig;
        infotmp.update(&pid, &val);
    }

    return 0;
};

int kretprobe__sys_kill(struct pt_regs *ctx)
{
    struct data_t data = {};
    struct val_t *valp;
    u32 pid = bpf_get_current_pid_tgid();
    u64 tsp = bpf_ktime_get_ns();

    valp = infotmp.lookup(&pid);
    if (valp == 0) {
        // missed entry
        return 0;
    }

    bpf_probe_read(&data.comm, sizeof(data.comm), valp->comm);
    data.pid = pid;
    data.delta = tsp - valp->ts;
    data.ts = tsp / 1000;
    data.tpid = valp->tpid;
    data.ret = PT_REGS_RC(ctx);
    data.sig = valp->sig;

    events.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&pid);

    return 0;
}
"""
if args.pid:
    bpf_text = bpf_text.replace('FILTER',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '')
if debug:
    print(bpf_text)

# initialize BPF
b = BPF(text=bpf_text)

TASK_COMM_LEN = 16    # linux/sched.h

class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulonglong),
        ("tpid", ct.c_ulonglong),
        ("sig", ct.c_int),
        ("ret", ct.c_int),
        ("ts", ct.c_ulonglong),
        ("delta", ct.c_ulonglong),
        ("comm", ct.c_char * TASK_COMM_LEN)
    ]

start_ts = 0
prev_ts = 0
delta = 0

# header
if args.timestamp:
    print("%-14s" % ("TIME(s)"), end="")
print("%-6s %-16s %-4s %-6s %s" % ("PID", "COMM", "SIG", "TPID", "RESULT"))

# process event
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    global start_ts
    global prev_ts
    global delta

    if start_ts == 0:
        prev_ts = start_ts

    if start_ts == 1:
        delta = float(delta) + (event.ts - prev_ts)

    if (args.failed and (event.ret >= 0)):
        start_ts = 1
        prev_ts = event.ts
        return

    # print columns
    if args.timestamp:
        print("%-14.9f" % (delta / 1000000), end="")

    print("%-6d %-16s %-4d %-6d %d" % (event.pid, event.comm, event.sig,
        event.tpid, event.ret))

    prev_ts = event.ts
    start_ts = 1

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    b.kprobe_poll()

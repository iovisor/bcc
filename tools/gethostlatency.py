#!/usr/bin/python
#
# gethostlatency  Show latency for getaddrinfo/gethostbyname[2] calls.
#                 For Linux, uses BCC, eBPF. Embedded C.
#
# This can be useful for identifying DNS latency, by identifying which
# remote host name lookups were slow, and by how much.
#
# This uses dynamic tracing of user-level functions and registers, and may
# need modifications to match your software and processor architecture.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 28-Jan-2016    Brendan Gregg   Created this.
# 30-Mar-2016   Allan McAleavy updated for BPF_PERF_OUTPUT

from __future__ import print_function
from bcc import BPF
from time import strftime
import ctypes as ct

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct val_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char host[80];
    u64 ts;
};

struct data_t {
    u32 pid;
    u64 ts;
    u64 delta;
    char comm[TASK_COMM_LEN];
    char host[80];
};

BPF_HASH(start, u32, struct val_t);
BPF_PERF_OUTPUT(events);

int do_entry(struct pt_regs *ctx) {
    if (!ctx->PT_REGS_PARM1)
        return 0;

    struct val_t val = {};
    u32 pid = bpf_get_current_pid_tgid();

    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        bpf_probe_read(&val.host, sizeof(val.host), (void *)ctx->PT_REGS_PARM1);
        val.pid = bpf_get_current_pid_tgid();
        val.ts = bpf_ktime_get_ns();
        start.update(&pid, &val);
    }

    return 0;
}

int do_return(struct pt_regs *ctx) {
    struct val_t *valp;
    struct data_t data = {};
    u64 delta;
    u32 pid = bpf_get_current_pid_tgid();

    u64 tsp = bpf_ktime_get_ns();

    valp = start.lookup(&pid);
    if (valp == 0)
        return 0;       // missed start

    bpf_probe_read(&data.comm, sizeof(data.comm), valp->comm);
    bpf_probe_read(&data.host, sizeof(data.host), (void *)valp->host);
    data.pid = valp->pid;
    data.delta = tsp - valp->ts;
    data.ts = tsp / 1000;
    events.perf_submit(ctx, &data, sizeof(data));
    start.delete(&pid);
    return 0;
}
"""
b = BPF(text=bpf_text)
b.attach_uprobe(name="c", sym="getaddrinfo", fn_name="do_entry")
b.attach_uprobe(name="c", sym="gethostbyname", fn_name="do_entry")
b.attach_uprobe(name="c", sym="gethostbyname2", fn_name="do_entry")
b.attach_uretprobe(name="c", sym="getaddrinfo", fn_name="do_return")
b.attach_uretprobe(name="c", sym="gethostbyname", fn_name="do_return")
b.attach_uretprobe(name="c", sym="gethostbyname2", fn_name="do_return")

TASK_COMM_LEN = 16    # linux/sched.h

class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulonglong),
        ("ts", ct.c_ulonglong),
        ("delta", ct.c_ulonglong),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("host", ct.c_char * 80)
    ]

start_ts = 0
prev_ts = 0
delta = 0

# header
print("%-9s %-6s %-16s %10s %s" % ("TIME", "PID", "COMM", "LATms", "HOST"))

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    global start_ts
    global prev_ts
    global delta

    if start_ts == 0:
        prev_ts = start_ts

    if start_ts == 1:
        delta = float(delta) + (event.ts - prev_ts)

    print("%-9s %-6d %-16s %10.2f %s" % (strftime("%H:%M:%S"), event.pid,
        event.comm, (event.delta / 1000000), event.host))

    prev_ts = event.ts
    start_ts = 1

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    b.kprobe_poll()

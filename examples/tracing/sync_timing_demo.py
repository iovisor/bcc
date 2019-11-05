#!/usr/bin/python
#
# sync_timing.py    Trace time between syncs.
#                   For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of tracing time between events.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u64 ts;
    u64 delta;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT[event];

int do_trace(struct pt_regs *ctx) {
    struct data_t data = {}

    data.pid = bpf_get_current_pid_tgid();
    if(data.ts == 0 || data.ts == NULL)
        data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    delta = bpf_ktime_get_ns() - data.ts;
    if (delta < 1000000000)
            delta = delta / 1000000;
    data.delta = delta;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
""")

b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
print("Tracing for quick sync's... Ctrl-C to end")

# format output
start = 0
def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
    if start == 0:
        start = event.ts
    event.ts = event.ts - start
    printb(b"At time %.2f s: multiple syncs detected, last %s ms ago" % (event.ts, event.delta))

b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# threadsnoop   List new thread creation.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# Copyright (c) 2019 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License").
# This was originally created for the BPF Performance Tools book
# published by Addison Wesley. ISBN-13: 9780136554820
# When copying or porting, include this comment.
#
# 02-Jul-2019   Brendan Gregg   Ported from bpftrace to BCC.

from __future__ import print_function
from bcc import BPF

# load BPF program
b = BPF(text="""
#include <linux/sched.h>

struct data_t {
    u64 ts;
    u32 pid;
    u64 start;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

void do_entry(struct pt_regs *ctx) {
    struct data_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.start = PT_REGS_PARM3(ctx);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));
};
""")

# Since version 2.34, pthread features are integrated in libc
try:
    b.attach_uprobe(name="pthread", sym="pthread_create", fn_name="do_entry")
except Exception:
    b.attach_uprobe(name="c", sym="pthread_create", fn_name="do_entry")

print("%-10s %-6s %-16s %s" % ("TIME(ms)", "PID", "COMM", "FUNC"))

start_ts = 0

# process event
def print_event(cpu, data, size):
    global start_ts
    event = b["events"].event(data)
    if start_ts == 0:
        start_ts = event.ts
    func = b.sym(event.start, event.pid)
    if (func == "[unknown]"):
        func = hex(event.start)
    print("%-10d %-6d %-16s %s" % ((event.ts - start_ts) / 1000000,
        event.pid, event.comm, func))

b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

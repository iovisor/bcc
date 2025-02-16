#!/usr/bin/python3
#
# setuid_monitor    A setuid syscall monitor, as the example of
#                   utilizing kernel tracepoint.
#
# Test by running the code. Meanwhile, run any command that introduces
# the setuid syscall, such as su, sudo, passwd, etc.
#
# Copyright 2025 HardenedLinux
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

# define BPF program
b = BPF(text="""
#include <linux/sched.h>

// define output data structure in C
struct data_t {
    u32 pid;
    u32 uid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_setuid) {
    struct data_t data = {};

    // Check /sys/kernel/debug/tracing/events/syscalls/sys_enter_setuid/format
    // for the args format
    data.uid = args->uid;
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(args, &data, sizeof(data));

    return 0;
}
""")

# header
print("%-14s %-12s %-6s %s" % ("TIME(s)", "COMMAND", "PID", "UID"))

def print_event(cpu, data, size):
    event = b["events"].event(data)
    printb(b"%-14.3f %-12s %-6d %d" % ((event.ts/1000000000), 
           event.comm, event.pid, event.uid))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

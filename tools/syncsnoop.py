#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# syncsnoop Trace sync() syscall.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of BCC trace & reformat. See
# examples/hello_world.py for a BCC trace with default output example.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Aug-2015   Brendan Gregg   Created this.
# 19-Feb-2016   Allan McAleavy migrated to BPF_PERF_OUTPUT
# 17-Jul-2024   Rong Tao        Support more sync syscalls.

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
import sys

# load BPF program
b = BPF(text="""
#include <linux/sched.h>

enum sync_syscalls {
    SYS_T_MIN,
    SYS_SYNC,
    SYS_FSYNC,
    SYS_FDATASYNC,
    SYS_MSYNC,
    SYS_SYNC_FILE_RANGE,
    SYS_SYNCFS,
    SYS_T_MAX,
};

struct data_t {
    char comm[TASK_COMM_LEN];
    u32 sys;
    u64 ts;
};

BPF_PERF_OUTPUT(events);

static void __syscall(void *ctx, enum sync_syscalls sys) {
    struct data_t data = {};

    bpf_get_current_comm(data.comm, sizeof(data.comm));
    data.ts = bpf_ktime_get_ns() / 1000;
    data.sys = sys;

    events.perf_submit(ctx, &data, sizeof(data));
};

void syscall__sync(void *ctx) {
    return __syscall(ctx, SYS_SYNC);
}

void syscall__fsync(void *ctx) {
    return __syscall(ctx, SYS_FSYNC);
}

void syscall__fdatasync(void *ctx) {
    return __syscall(ctx, SYS_FDATASYNC);
}

void syscall__msync(void *ctx) {
    return __syscall(ctx, SYS_MSYNC);
}

void syscall__sync_file_range(void *ctx) {
    return __syscall(ctx, SYS_SYNC_FILE_RANGE);
}

void syscall__syncfs(void *ctx) {
    return __syscall(ctx, SYS_SYNCFS);
}
""")

class EventType(object):
    SYS_SYNC = 1,
    SYS_FSYNC = 2,
    SYS_FDATASYNC = 3,
    SYS_MSYNC = 4,
    SYS_SYNC_FILE_RANGE = 5,
    SYS_SYNCFS = 6,

sys_names = (
    "N/A",
    "sync",
    "fsync",
    "fdatasync",
    "msync",
    "sync_file_range",
    "syncfs",
    "N/A",
)

b.attach_kprobe(event=b.get_syscall_fnname("sync"),
                fn_name="syscall__sync")
b.attach_kprobe(event=b.get_syscall_fnname("fsync"),
                fn_name="syscall__fsync")
b.attach_kprobe(event=b.get_syscall_fnname("fdatasync"),
                fn_name="syscall__fdatasync")
b.attach_kprobe(event=b.get_syscall_fnname("msync"),
                fn_name="syscall__msync")
b.attach_kprobe(event=b.get_syscall_fnname("sync_file_range"),
                fn_name="syscall__sync_file_range")
b.attach_kprobe(event=b.get_syscall_fnname("syncfs"),
                fn_name="syscall__syncfs")

# header
print("%-18s %-16s %-16s" % ("TIME(s)", "COMM", "CALL"))

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    printb(b"%-18.9f %-16s" % (float(event.ts) / 1000000, event.comm), nl="")
    print(" %-16s" % sys_names[event.sys])
    sys.stdout.flush()

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

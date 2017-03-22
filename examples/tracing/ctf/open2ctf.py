#!/usr/bin/env python3
#
# open2ctf.py
#
# Basic example of using CTF module to format and store sys_open events
# in Common Trace Format (CTF)
#
# A Ctrl-C stops the trace recording. View the trace with babeltrace
#
# Copyright (c) 2017 ShiftLeft Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# Author(s):
#   Suchakrapani Sharma <suchakra@shiftleft.io>

from bcc import BPF, CTF, CTFEvent
import ctypes as ct

# BPF program
prog = """
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>

struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
};
BPF_PERF_OUTPUT(events);

int handler(struct pt_regs *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read(&data.fname, sizeof(data.fname),
                  (void *)PT_REGS_PARM1(ctx));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# Load BPF program
b = BPF(text=prog)
b.attach_kprobe(event="sys_open", fn_name="handler")

# Get output data
TASK_COMM_LEN = 16  # linux/sched.h
NAME_MAX = 255  # uapi/linux/limits.h


class Data(ct.Structure):
    _fields_ = [("pid", ct.c_uint),
                ("ts", ct.c_ulonglong),
                ("comm", ct.c_char * TASK_COMM_LEN),
                ("fname", ct.c_char * NAME_MAX)]

fields = {"pid": CTF.Type.u32, "comm": CTF.Type.string,
          "filename": CTF.Type.string}
c = CTF("sys_open", "/tmp/opentrace", fields)


def write_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    ev = CTFEvent(c)
    ev.time(c, int(event.ts))
    ev.payload('pid', event.pid)
    ev.payload('comm', event.comm.decode())
    ev.payload('filename', event.fname.decode())
    ev.write(c, cpu)

b["events"].open_perf_buffer(write_event)
while 1:
    b.kprobe_poll()

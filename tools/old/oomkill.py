#!/usr/bin/env python
#
# oomkill   Trace oom_kill_process(). For Linux, uses BCC, eBPF.
#
# This traces the kernel out-of-memory killer, and prints basic details,
# including the system load averages. This can provide more context on the
# system state at the time of OOM: was it getting busier or steady, based
# on the load averages? This tool may also be useful to customize for
# investigations; for example, by adding other task_struct details at the time
# of OOM.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 09-Feb-2016   Brendan Gregg   Created this.

from bcc import BPF
from time import strftime
import ctypes as ct

# linux stats
loadavg = "/proc/loadavg"

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/oom.h>

struct data_t {
    u64 fpid;
    u64 tpid;
    u64 pages;
    char fcomm[TASK_COMM_LEN];
    char tcomm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

void kprobe__oom_kill_process(struct pt_regs *ctx, struct oom_control *oc,
    struct task_struct *p, unsigned int points, unsigned long totalpages)
{
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid();
    data.fpid = pid;
    data.tpid = p->pid;
    data.pages = totalpages;
    bpf_get_current_comm(&data.fcomm, sizeof(data.fcomm));
    bpf_probe_read(&data.tcomm, sizeof(data.tcomm), p->comm);
    events.perf_submit(ctx, &data, sizeof(data));
}
"""

# kernel->user event data: struct data_t
TASK_COMM_LEN = 16  # linux/sched.h
class Data(ct.Structure):
    _fields_ = [
        ("fpid", ct.c_ulonglong),
        ("tpid", ct.c_ulonglong),
        ("pages", ct.c_ulonglong),
        ("fcomm", ct.c_char * TASK_COMM_LEN),
        ("tcomm", ct.c_char * TASK_COMM_LEN)
    ]

# process event
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    with open(loadavg) as stats:
        avgline = stats.read().rstrip()
    print(("%s Triggered by PID %d (\"%s\"), OOM kill of PID %d (\"%s\")"
        ", %d pages, loadavg: %s") % (strftime("%H:%M:%S"), event.fpid,
        event.fcomm.decode('utf-8', 'replace'), event.tpid,
        event.tcomm.decode('utf-8', 'replace'), event.pages, avgline))

# initialize BPF
b = BPF(text=bpf_text)
print("Tracing OOM kills... Ctrl-C to stop.")
b["events"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()

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

# linux stats
loadavg = "/proc/loadavg"

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/oom.h>

struct data_t {
    u32 fpid;
    u32 tpid;
    u64 pages;
    u32 stack_id;
    char fcomm[TASK_COMM_LEN];
    char tcomm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);
BPF_STACK_TRACE(stack_traces, 1024);

void kprobe__oom_kill_process(struct pt_regs *ctx, struct oom_control *oc, const char *message)
{
    struct task_struct *p = oc->chosen;
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    data.fpid = pid;
    data.tpid = p->tgid;
    data.pages = oc->totalpages;
    bpf_get_current_comm(&data.fcomm, sizeof(data.fcomm));
    bpf_probe_read_kernel(&data.tcomm, sizeof(data.tcomm), p->comm);

    // Capture the user stack trace
    data.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    events.perf_submit(ctx, &data, sizeof(data));
}
"""

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    with open(loadavg) as stats:
        avgline = stats.read().rstrip()
    print(("%s Triggered by PID %d (\"%s\"), OOM kill of PID %d (\"%s\")"
        ", %d pages, loadavg: %s") % (strftime("%H:%M:%S"), event.fpid,
        event.fcomm.decode('utf-8', 'replace'), event.tpid,
        event.tcomm.decode('utf-8', 'replace'), event.pages, avgline))

    # Print the stack trace if stack_id is non-negative
    if event.stack_id >= 0:
        print("  Stack trace:")
        stack_traces = b["stack_traces"]
        for addr in stack_traces.walk(event.stack_id):
            print(f"    {b.sym(addr, event.tpid)}")
    else:
        print("  Failed to capture stack trace")

# initialize BPF
b = BPF(text=bpf_text)
print("Tracing OOM kills... Ctrl-C to stop.")
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

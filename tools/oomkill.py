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

# initialize BPF
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/oom.h>
void kprobe__oom_kill_process(struct pt_regs *ctx, struct oom_control *oc,
    struct task_struct *p, unsigned int points, unsigned long totalpages)
{
    bpf_trace_printk("OOM kill of PID %d (\\"%s\\"), %d pages\\n", p->pid,
        p->comm, totalpages);
}
""")

# print output
print("Tracing oom_kill_process()... Ctrl-C to end.")
while 1:
    (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    with open(loadavg) as stats:
        avgline = stats.read().rstrip()
    print("%s Triggered by PID %d (\"%s\"), %s, loadavg: %s" % (
        strftime("%H:%M:%S"), pid, task, msg, avgline))

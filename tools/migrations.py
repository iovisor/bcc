#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# migrations    Trace as processes migrate between CPUs.
#               For Linux, uses BCC, eBPF.
#
# This script traces as tasks migrate between CPUs
# by taking note of the cpu the current process was
# scheduled previously.
#
# USAGE: migrations [-p PID]
#
# REQUIRES: Linux 4.9+ (BPF_PROG_TYPE_PERF_EVENT support).
# 
# This observes processes migrating from one CPU to another.
# It is also possible to observe only a specific PID or
# by default all threads, except the swapper thread.
# 
# Copyright 2019 Cloudflare, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 27-Oct-2019   Gergely Bod   Created this.

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime

# arguments
examples = """examples:
    ./migrations          # trace all process migrations system wide
    ./migrations -p 123   # trace pid 123 only
"""
parser = argparse.ArgumentParser(
    description="Trace process cpu migrations.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", type=int, metavar="PID", dest="pid",
    help="trace this PID only")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>

BPF_HASH(start, u32, u32);

struct rq;

struct data_t {
    u32 pid;
    char task[TASK_COMM_LEN];
    u32 prev_cpu;
    u32 next_cpu;
};

BPF_PERF_OUTPUT(events);

// record enqueue cpu
static int trace_enqueue(u32 pid, u32 cpu)
{
    if (FILTER_PID || pid == 0)
        return 0;
    // u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &cpu);
    return 0;
}
"""

bpf_text_kprobe = """
int trace_wake_up_new_task(struct pt_regs *ctx, struct task_struct *p)
{
    return trace_enqueue(p->pid, p->cpu);
}

int trace_ttwu_do_wakeup(struct pt_regs *ctx, struct rq *rq, struct task_struct *p,
    int wake_flags)
{
    return trace_enqueue(p->pid, p->cpu);
}

// watch for task migration
int trace_run(struct pt_regs *ctx, struct task_struct *prev)
{
    u32 pid;
    u32* prev_cpu;
    u32  next_cpu;
    struct task_struct *next;

    next = (struct task_struct *)bpf_get_current_task();
    if(!next)
        return 0;

    pid = next->pid;
    next_cpu = next->cpu;

    if(FILTER_PID || pid == 0)
        return 0;

    prev_cpu = start.lookup_or_init(&pid, &next_cpu);
    if(!prev_cpu)
        return 0;

    if(next_cpu == *prev_cpu) {
        return 0;
    }
    
    struct data_t data = {};
    data.pid = pid;
    bpf_probe_read_str(&data.task, sizeof(data.task), next->comm);
    data.prev_cpu = *prev_cpu;
    data.next_cpu = next_cpu;

    // output
    events.perf_submit(ctx, &data, sizeof(data));

    start.delete(&pid);
    return 0;
}
"""

bpf_text_raw_tp = """
RAW_TRACEPOINT_PROBE(sched_wakeup)
{
    // TP_PROTO(struct task_struct *p)
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    return trace_enqueue(p->pid, p->cpu);
}

RAW_TRACEPOINT_PROBE(sched_wakeup_new)
{
    // TP_PROTO(struct task_struct *p)
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    u32 pid;
    u32 cpu;

    bpf_probe_read(&pid, sizeof(pid), &p->pid);
    bpf_probe_read(&cpu, sizeof(cpu), &p->cpu);
    return trace_enqueue(pid, cpu);
}

RAW_TRACEPOINT_PROBE(sched_switch)
{
    // TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next)
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next = (struct task_struct *)ctx->args[2];
    u32 pid;
    u32* prev_cpu;
    u32  next_cpu;

    bpf_probe_read(&pid, sizeof(next->pid), &next->pid);
    bpf_probe_read(&next_cpu, sizeof(next->cpu), &next->cpu);

    if(FILTER_PID || pid == 0)
        return 0;
    
    prev_cpu = start.lookup_or_init(&pid, &next_cpu);
    if(!prev_cpu)
        return 0;

    if(next_cpu == *prev_cpu)
        return 0;

    struct data_t data = {};
    data.pid = pid;
    bpf_probe_read_str(&data.task, sizeof(data.task), next->comm);
    data.prev_cpu = *prev_cpu;
    data.next_cpu = next_cpu;

    // output
    events.perf_submit(ctx, &data, sizeof(data));

    start.delete(&pid);
    return 0;
}
"""

is_support_raw_tp = BPF.support_raw_tracepoint()
if is_support_raw_tp:
    bpf_text += bpf_text_raw_tp
else:
    bpf_text += bpf_text_kprobe

# code substitutions
if args.pid:
    bpf_text = bpf_text.replace('FILTER_PID', 'pid != %s' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER_PID', '0')
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%-8s %-16s %-6s %10s %14s" % (strftime("%H:%M:%S"), event.task, event.pid, 
                            event.prev_cpu, event.next_cpu))

# load BPF program
b = BPF(text=bpf_text)
if not is_support_raw_tp:
    b.attach_kprobe(event="ttwu_do_wakeup", fn_name="trace_ttwu_do_wakeup")
    b.attach_kprobe(event="wake_up_new_task", fn_name="trace_wake_up_new_task")
    b.attach_kprobe(event="finish_task_switch", fn_name="trace_run")

print("Tracing CPU migrations.")
print("%-8s %-16s %-6s %14s %14s" % ("TIME", "COMM", "PID", "PREV_CPU", "CURR_CPU"))

# read events
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

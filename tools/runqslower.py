#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# runqslower    Trace long process scheduling delays.
#               For Linux, uses BCC, eBPF.
#
# This script traces high scheduling delays between tasks being
# ready to run and them running on CPU after that.
#
# USAGE: runqslower [-p PID] [min_us]
#
# REQUIRES: Linux 4.9+ (BPF_PROG_TYPE_PERF_EVENT support).
#
# This measures the time a task spends waiting on a run queue for a turn
# on-CPU, and shows this time as a individual events. This time should be small,
# but a task may need to wait its turn due to CPU load.
#
# This measures two types of run queue latency:
# 1. The time from a task being enqueued on a run queue to its context switch
#    and execution. This traces ttwu_do_wakeup(), wake_up_new_task() ->
#    finish_task_switch() with either raw tracepoints (if supported) or kprobes
#    and instruments the run queue latency after a voluntary context switch.
# 2. The time from when a task was involuntary context switched and still
#    in the runnable state, to when it next executed. This is instrumented
#    from finish_task_switch() alone.
#
# Copyright 2016 Cloudflare, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 02-May-2018   Ivan Babrou   Created this.

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime
import ctypes as ct

# arguments
examples = """examples:
    ./runqslower         # trace run queue latency higher than 10000 us (default)
    ./runqslower 1000    # trace run queue latency higher than 1000 us
    ./runqslower -p 123  # trace pid 123 only
"""
parser = argparse.ArgumentParser(
    description="Trace high run queue latency",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", type=int, metavar="PID", dest="pid",
    help="trace this PID only")
parser.add_argument("min_us", nargs="?", default='10000',
    help="minimum run queue latecy to trace, in ms (default 10000)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
min_us = int(args.min_us)
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>

BPF_HASH(start, u32);

struct rq;

struct data_t {
    u32 pid;
    char task[TASK_COMM_LEN];
    u64 delta_us;
};

BPF_PERF_OUTPUT(events);

// record enqueue timestamp
static int trace_enqueue(u32 tgid, u32 pid)
{
    if (FILTER_PID || pid == 0)
        return 0;
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    return 0;
}
"""

bpf_text_kprobe = """
int trace_wake_up_new_task(struct pt_regs *ctx, struct task_struct *p)
{
    return trace_enqueue(p->tgid, p->pid);
}

int trace_ttwu_do_wakeup(struct pt_regs *ctx, struct rq *rq, struct task_struct *p,
    int wake_flags)
{
    return trace_enqueue(p->tgid, p->pid);
}

// calculate latency
int trace_run(struct pt_regs *ctx, struct task_struct *prev)
{
    u32 pid, tgid;

    // ivcsw: treat like an enqueue event and store timestamp
    if (prev->state == TASK_RUNNING) {
        tgid = prev->tgid;
        pid = prev->pid;
        if (!(FILTER_PID || pid == 0)) {
            u64 ts = bpf_ktime_get_ns();
            start.update(&pid, &ts);
        }
    }

    tgid = bpf_get_current_pid_tgid() >> 32;
    pid = bpf_get_current_pid_tgid();

    u64 *tsp, delta_us;

    // fetch timestamp and calculate delta
    tsp = start.lookup(&pid);
    if (tsp == 0) {
        return 0;   // missed enqueue
    }
    delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;

    if (FILTER_US)
        return 0;

    struct data_t data = {};
    data.pid = pid;
    data.delta_us = delta_us;
    bpf_get_current_comm(&data.task, sizeof(data.task));

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
    return trace_enqueue(p->tgid, p->pid);
}

RAW_TRACEPOINT_PROBE(sched_wakeup_new)
{
    // TP_PROTO(struct task_struct *p)
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    u32 tgid, pid;

    bpf_probe_read(&tgid, sizeof(tgid), &p->tgid);
    bpf_probe_read(&pid, sizeof(pid), &p->pid);
    return trace_enqueue(tgid, pid);
}

RAW_TRACEPOINT_PROBE(sched_switch)
{
    // TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next)
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next= (struct task_struct *)ctx->args[2];
    u32 pid, tgid;
    long state;

    // ivcsw: treat like an enqueue event and store timestamp
    bpf_probe_read(&state, sizeof(long), &prev->state);
    if (state == TASK_RUNNING) {
        bpf_probe_read(&tgid, sizeof(prev->tgid), &prev->tgid);
        bpf_probe_read(&pid, sizeof(prev->pid), &prev->pid);
        if (!(FILTER_PID || pid == 0)) {
            u64 ts = bpf_ktime_get_ns();
            start.update(&pid, &ts);
        }
    }

    bpf_probe_read(&tgid, sizeof(next->tgid), &next->tgid);
    bpf_probe_read(&pid, sizeof(next->pid), &next->pid);

    u64 *tsp, delta_us;

    // fetch timestamp and calculate delta
    tsp = start.lookup(&pid);
    if (tsp == 0) {
        return 0;   // missed enqueue
    }
    delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;

    if (FILTER_US)
        return 0;

    struct data_t data = {};
    data.pid = pid;
    data.delta_us = delta_us;
    bpf_get_current_comm(&data.task, sizeof(data.task));

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
if min_us == 0:
    bpf_text = bpf_text.replace('FILTER_US', '0')
else:
    bpf_text = bpf_text.replace('FILTER_US', 'delta_us <= %s' % str(min_us))
if args.pid:
    bpf_text = bpf_text.replace('FILTER_PID', 'pid != %s' % pid)
else:
    bpf_text = bpf_text.replace('FILTER_PID', '0')
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# kernel->user event data: struct data_t
DNAME_INLINE_LEN = 32   # linux/dcache.h
TASK_COMM_LEN = 16      # linux/sched.h
class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("task", ct.c_char * TASK_COMM_LEN),
        ("delta_us", ct.c_ulonglong),
    ]

# process event
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print("%-8s %-16s %-6s %14s" % (strftime("%H:%M:%S"), event.task, event.pid, event.delta_us))

# load BPF program
b = BPF(text=bpf_text)
if not is_support_raw_tp:
    b.attach_kprobe(event="ttwu_do_wakeup", fn_name="trace_ttwu_do_wakeup")
    b.attach_kprobe(event="wake_up_new_task", fn_name="trace_wake_up_new_task")
    b.attach_kprobe(event="finish_task_switch", fn_name="trace_run")

print("Tracing run queue latency higher than %d us" % min_us)
print("%-8s %-16s %-6s %14s" % ("TIME", "COMM", "PID", "LAT(us)"))

# read events
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    b.perf_buffer_poll()

#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# dslower    Trace process block on D state time. (uninterruptible sleep)
#               For Linux, uses BCC, eBPF.
#
# This script traces long process block time(in D state)
#
# USAGE: dslower [-p PID] [-t TID] [-P] [min_us]
#
# REQUIRES: Linux 4.9+ (BPF_PROG_TYPE_PERF_EVENT support).
#
# This measures the time between a task was switched off cpu because of uninterruptible sleep and 
# been woken up.
# ie. sched_switch -> ttwu_do_wakeup
# Copyright 2022 Tencent
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 28-Nov-2022   Curu Wong

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime

# arguments
examples = """examples:
    ./dslower         # trace process block longer than 10000 us (default)
    ./dslower 1000    # trace process block longer than 1000 us
    ./dslower -p 123  # trace pid 123
    ./dslower -t 123  # trace tid 123 (use for threads only)
    ./dslower -s  # also show stack trace

"""
parser = argparse.ArgumentParser(
    description="Trace process block on D state time. (uninterruptible sleep)",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("min_us", nargs="?", default='10000',
    help="minimum block time to trace, in us (default 10000)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)

thread_group = parser.add_mutually_exclusive_group()
thread_group.add_argument("-p", "--pid", metavar="PID", dest="pid",
    help="trace this PID only", type=int)
thread_group.add_argument("-t", "--tid", metavar="TID", dest="tid",
    help="trace this TID only", type=int)

parser.add_argument("-s", "--stack", action="store_true",
    help="also show block stack trace")

args = parser.parse_args()

min_us = int(args.min_us)
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>

#ifndef TASK_NOLOAD
#define TASK_NOLOAD         0x0400
#endif

struct ts_stack_t {
    u32 stack_id;
    u64 ts;
};
BPF_ARRAY(start, struct ts_stack_t, MAX_PID);

struct rq;

BPF_STACK_TRACE(stack_traces, 4096);

struct data_t {
    u32 pid;
    u32 stack_id;
    char task[TASK_COMM_LEN];
    u64 delta_us;
};

BPF_PERF_OUTPUT(events);
"""

bpf_text_kprobe = """
//int trace_finish_task_switch(struct pt_regs *ctx, struct task_struct *prev)
int trace_finish_task_switch(struct pt_regs *ctx, struct rq *rq, struct task_struct *prev)
{
    u32 pid, tgid;
    u64 ts = bpf_ktime_get_ns();

    // prev task go to sleep
    if ((prev->STATE_FIELD & TASK_UNINTERRUPTIBLE) && !(prev->STATE_FIELD & TASK_NOLOAD)) {
        pid = prev->pid;
        tgid = prev->tgid;
        if (pid != 0) {
            if (!(FILTER_PID) && !(FILTER_TGID)) {
                struct ts_stack_t ts_stack = { .ts = ts };
                start.update(&pid, &ts_stack);
            }
        }
    }

    /* finish_task_switch already switched stack, so we can't get stack trace of prev task
     *  we need to get the stack after the same task sched in again.
     *  the accurate delta should between sched_swith -> sched_wakeup
     *  the delta caculated here is longer than real block time, this is indeed  block_time + run_delay
    */
    pid = bpf_get_current_pid_tgid();
    struct ts_stack_t *ts_stack_p = start.lookup(&pid);

    u64 delta_us;
    if ((ts_stack_p == 0) || (ts_stack_p->ts == 0)) {
        return 0;   // missed enqueue
    }

    if(ts < ts_stack_p->ts){
        //maybe time wrap
        ts_stack_p->ts = 0;
        return 0;
    }

    delta_us = (ts - ts_stack_p->ts) / 1000;
    ts_stack_p->ts = 0;

    if (FILTER_US){
        return 0;
    }

    struct data_t data = {};
    data.pid = pid;
    data.delta_us = delta_us;
    bpf_get_current_comm(&data.task, sizeof(data.task));
#ifdef SHOW_STACK
    data.stack_id = stack_traces.get_stackid(ctx, 0);
#endif

    // output
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;

}
"""

bpf_text_raw_tp = """
RAW_TRACEPOINT_PROBE(sched_wakeup)
{
    // TP_PROTO(struct task_struct *p)
    struct task_struct *p = (struct task_struct *)ctx->args[0];

    u64 *tsp, delta_us;
    u32 pid = p->pid;
    u32 tgid = p->tgid;

    if (FILTER_PID || FILTER_TGID || pid == 0)
        return 0;

    u64 ts = bpf_ktime_get_ns();

    // fetch timestamp and calculate delta
    struct ts_stack_t *ts_stack_p = start.lookup(&pid);
    if ((ts_stack_p == 0) || (ts_stack_p->ts == 0)) {
        return 0;   // missed enqueue
    }

    if(ts < ts_stack_p->ts){
        //maybe time wrap
        ts_stack_p->ts = 0;
        return 0;
    }

    delta_us = (ts - ts_stack_p->ts) / 1000;
    ts_stack_p->ts = 0;

    if (FILTER_US){
        return 0;
    }

    struct data_t data = {};
    data.pid = pid;
    data.delta_us = delta_us;
    bpf_probe_read(&data.task, sizeof(data.task), p->comm);
    data.stack_id = ts_stack_p->stack_id;

    // output
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

RAW_TRACEPOINT_PROBE(sched_switch)
{
    // TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next)
    struct task_struct *prev = (struct task_struct *)ctx->args[1];

    u32 pid, tgid;

    // prev task go to sleep
    if ((prev->STATE_FIELD & TASK_UNINTERRUPTIBLE) && !(prev->STATE_FIELD & TASK_NOLOAD)) {
        pid = prev->pid;
        tgid = prev->tgid;
        u64 ts = bpf_ktime_get_ns();
        if (pid != 0) {
            if (!(FILTER_PID) && !(FILTER_TGID)) {
                struct ts_stack_t ts_stack = { .ts = ts };
#ifdef SHOW_STACK
                ts_stack.stack_id = stack_traces.get_stackid(ctx, 0);
#endif
                start.update(&pid, &ts_stack);
            }
        }
    }
    return 0;
}
"""

is_support_raw_tp = BPF.support_raw_tracepoint()
if is_support_raw_tp:
    bpf_text += bpf_text_raw_tp
else:
    bpf_text += bpf_text_kprobe

# code substitutions
if BPF.kernel_struct_has_field(b'task_struct', b'__state') == 1:
    bpf_text = bpf_text.replace('STATE_FIELD', '__state')
else:
    bpf_text = bpf_text.replace('STATE_FIELD', 'state')
if min_us == 0:
    bpf_text = bpf_text.replace('FILTER_US', '0')
else:
    bpf_text = bpf_text.replace('FILTER_US', 'delta_us <= %s' % str(min_us))

if args.tid:
    bpf_text = bpf_text.replace('FILTER_PID', 'pid != %s' % args.tid)
else:
    bpf_text = bpf_text.replace('FILTER_PID', '0')

if args.pid:
    bpf_text = bpf_text.replace('FILTER_TGID', 'tgid != %s' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER_TGID', '0')

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%-8s [%03d] %-16s %-7s %d" % (strftime("%H:%M:%S"), cpu, event.task.decode('utf-8', 'replace'), event.pid, event.delta_us))
    if args.stack:
        for addr in stack_traces.walk(event.stack_id):
            sym = b.ksym(addr, show_offset=True).decode('utf-8', 'replace')
            print("\t%s" % sym)

max_pid = int(open("/proc/sys/kernel/pid_max").read())

# load BPF program
cflags = ["-DMAX_PID=%d" % max_pid]
if args.stack:
    cflags.append("-DSHOW_STACK")
b = BPF(text=bpf_text, cflags=cflags)
if not is_support_raw_tp:
    b.attach_kprobe(event_re="^finish_task_switch$|^finish_task_switch\.isra\.\d$",
                    fn_name="trace_finish_task_switch")
print("Tracing block time longer higher than %d us" % min_us)
print("%-8s %-5s %-16s %-7s %s" % ("TIME","CPU", "COMM", "TID", "LAT(us)"))

stack_traces = b.get_table("stack_traces")

# read events
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

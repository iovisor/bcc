#!/usr/bin/env python
#
# wakeuptime    Summarize sleep to wakeup time by waker kernel stack
#               For Linux, uses BCC, eBPF.
#
# USAGE: wakeuptime [-h] [-u] [-p PID] [-v] [-f] [duration]
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Jan-2016	Brendan Gregg	Created this.
# 03-Apr-2023	Rocky Xing   	Modified the order of stack output.
# 04-Apr-2023   Rocky Xing      Updated default stack storage size.

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from time import sleep
import argparse
import signal
import errno
from sys import stderr

# arg validation
def positive_int(val):
    try:
        ival = int(val)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")

    if ival < 0:
        raise argparse.ArgumentTypeError("must be positive")
    return ival

def positive_nonzero_int(val):
    ival = positive_int(val)
    if ival == 0:
        raise argparse.ArgumentTypeError("must be nonzero")
    return ival

# arguments
examples = """examples:
    ./wakeuptime             # trace blocked time with waker stacks
    ./wakeuptime 5           # trace for 5 seconds only
    ./wakeuptime -f 5        # 5 seconds, and output in folded format
    ./wakeuptime -u          # don't include kernel threads (user only)
    ./wakeuptime -p 185      # trace for PID 185 only
"""
parser = argparse.ArgumentParser(
    description="Summarize sleep to wakeup time by waker kernel stack",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-u", "--useronly", action="store_true",
    help="user threads only (no kernel threads)")
parser.add_argument("-p", "--pid",
    type=positive_int,
    help="trace this PID only")
parser.add_argument("-v", "--verbose", action="store_true",
    help="show raw addresses")
parser.add_argument("-f", "--folded", action="store_true",
    help="output folded format")
parser.add_argument("--stack-storage-size", default=16384,
    type=positive_nonzero_int,
    help="the number of unique stack traces that can be stored and "
         "displayed (default 16384)")
parser.add_argument("duration", nargs="?", default=99999999,
    type=positive_nonzero_int,
    help="duration of trace, in seconds")
parser.add_argument("-m", "--min-block-time", default=1,
    type=positive_nonzero_int,
    help="the amount of time in microseconds over which we " +
         "store traces (default 1)")
parser.add_argument("-M", "--max-block-time", default=(1 << 64) - 1,
    type=positive_nonzero_int,
    help="the amount of time in microseconds under which we " +
         "store traces (default U64_MAX)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
folded = args.folded
duration = int(args.duration)
debug = 0
if args.pid and args.useronly:
    parser.error("use either -p or -u.")

# signal handler
def signal_ignore(signal, frame):
    print()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MINBLOCK_US    MINBLOCK_US_VALUEULL
#define MAXBLOCK_US    MAXBLOCK_US_VALUEULL

struct key_t {
    int  w_k_stack_id;
    char waker[TASK_COMM_LEN];
    char target[TASK_COMM_LEN];
};
BPF_HASH(counts, struct key_t);
BPF_HASH(start, u32);
BPF_STACK_TRACE(stack_traces, STACK_STORAGE_SIZE);

static int offcpu_sched_switch() {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    struct task_struct *p = (struct task_struct *) bpf_get_current_task();
    u64 ts;

    if (FILTER)
        return 0;

    ts = bpf_ktime_get_ns();
    start.update(&tid, &ts);
    return 0;
}

static int wakeup(ARG0, struct task_struct *p) {
    u32 pid = p->tgid;
    u32 tid = p->pid;
    u64 delta, *tsp, ts;

    tsp = start.lookup(&tid);
    if (tsp == 0)
        return 0;        // missed start
    start.delete(&tid);

    if (FILTER)
        return 0;

    // calculate delta time
    delta = bpf_ktime_get_ns() - *tsp;
    delta = delta / 1000;
    if ((delta < MINBLOCK_US) || (delta > MAXBLOCK_US))
        return 0;

    struct key_t key = {};

    key.w_k_stack_id = stack_traces.get_stackid(ctx, 0);
    bpf_probe_read_kernel(&key.target, sizeof(key.target), p->comm);
    bpf_get_current_comm(&key.waker, sizeof(key.waker));

    counts.atomic_increment(key, delta);
    return 0;
}
"""

bpf_text_kprobe = """
int offcpu(struct pt_regs *ctx) {
    return offcpu_sched_switch();
}

int waker(struct pt_regs *ctx, struct task_struct *p) {
    return wakeup(ctx, p);
}
"""

bpf_text_raw_tp = """
RAW_TRACEPOINT_PROBE(sched_switch)
{
    // TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next)
    return offcpu_sched_switch();
}

RAW_TRACEPOINT_PROBE(sched_wakeup)
{
    // TP_PROTO(struct task_struct *p)
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    return wakeup(ctx, p);
}
"""

is_supported_raw_tp = BPF.support_raw_tracepoint()
if is_supported_raw_tp:
    bpf_text += bpf_text_raw_tp
else:
    bpf_text += bpf_text_kprobe

if args.pid:
    filter = 'pid != %s' % args.pid
elif args.useronly:
    filter = 'p->flags & PF_KTHREAD'
else:
    filter = '0'
bpf_text = bpf_text.replace('FILTER', filter)

if is_supported_raw_tp:
    arg0 = 'struct bpf_raw_tracepoint_args *ctx'
else:
    arg0 = 'struct pt_regs *ctx'
bpf_text = bpf_text.replace('ARG0', arg0)

# set stack storage size
bpf_text = bpf_text.replace('STACK_STORAGE_SIZE', str(args.stack_storage_size))
bpf_text = bpf_text.replace('MINBLOCK_US_VALUE', str(args.min_block_time))
bpf_text = bpf_text.replace('MAXBLOCK_US_VALUE', str(args.max_block_time))

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text)
if not is_supported_raw_tp:
    b.attach_kprobe(event="schedule", fn_name="offcpu")
    b.attach_kprobe(event="try_to_wake_up", fn_name="waker")
    matched = b.num_open_kprobes()
    if matched == 0:
        print("0 functions traced. Exiting.")
        exit()

# header
if not folded:
    print("Tracing blocked time (us) by kernel stack", end="")
    if duration < 99999999:
        print(" for %d secs." % duration)
    else:
        print("... Hit Ctrl-C to end.")

# output
while (1):
    try:
        sleep(duration)
    except KeyboardInterrupt:
        # as cleanup can take many seconds, trap Ctrl-C:
        signal.signal(signal.SIGINT, signal_ignore)

    if not folded:
        print()
    missing_stacks = 0
    has_enomem = False
    counts = b.get_table("counts")
    stack_traces = b.get_table("stack_traces")
    for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
        # handle get_stackid errors
        # check for an ENOMEM error
        if k.w_k_stack_id == -errno.ENOMEM:
            missing_stacks += 1
            continue

        waker_kernel_stack = [] if k.w_k_stack_id < 1 else \
            list(stack_traces.walk(k.w_k_stack_id))[1:]

        if folded:
            # print folded stack output
            line = \
                [k.waker] + \
                [b.ksym(addr)
                    for addr in reversed(waker_kernel_stack)] + \
                [k.target]
            printb(b"%s %d" % (b";".join(line), v.value))
        else:
            # print default multi-line stack output
            printb(b"    %-16s %s" % (b"target:", k.target))
            for addr in waker_kernel_stack:
                printb(b"    %-16x %s" % (addr, b.ksym(addr)))
            printb(b"    %-16s %s" % (b"waker:", k.waker))
            print("        %d\n" % v.value)
    counts.clear()

    if missing_stacks > 0:
        enomem_str = " Consider increasing --stack-storage-size."
        print("WARNING: %d stack traces could not be displayed.%s" %
            (missing_stacks, enomem_str),
            file=stderr)

    if not folded:
        print("Detaching...")
    exit()

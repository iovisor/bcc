#!/usr/bin/python
#
# offcputime    Summarize off-CPU time by kernel stack trace
#               For Linux, uses BCC, eBPF.
#
# USAGE: offcputime [-h] [-p PID | -u | -k] [-f] [duration]
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Jan-2016	Brendan Gregg	Created this.

from __future__ import print_function
from bcc import BPF
from sys import stderr
from time import sleep, strftime
import argparse
import signal

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
    ./offcputime             # trace off-CPU stack time until Ctrl-C
    ./offcputime 5           # trace for 5 seconds only
    ./offcputime -f 5        # 5 seconds, and output in folded format
    ./offcputime -p 185      # only trace threads for PID 185
    ./offcputime -u          # only trace user threads (no kernel)
    ./offcputime -k          # only trace kernel threads (no user)
"""
parser = argparse.ArgumentParser(
    description="Summarize off-CPU time by kernel stack trace",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
thread_group = parser.add_mutually_exclusive_group()
thread_group.add_argument("-p", "--pid", type=positive_int,
    help="trace this PID only")
thread_group.add_argument("-k", "--kernel-threads-only", action="store_true",
    help="kernel threads only (no user threads)")
thread_group.add_argument("-u", "--user-threads-only", action="store_true",
    help="user threads only (no kernel threads)")
parser.add_argument("-f", "--folded", action="store_true",
    help="output folded format")
parser.add_argument("--stack-storage-size", default=1024,
    type=positive_nonzero_int,
    help="the number of unique stack traces that can be stored and " \
        "displayed (default 1024)")
parser.add_argument("duration", nargs="?", default=99999999,
    type=positive_nonzero_int,
    help="duration of trace, in seconds")
args = parser.parse_args()
folded = args.folded
duration = int(args.duration)

# signal handler
def signal_ignore(signal, frame):
    print()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MINBLOCK_US	1

struct key_t {
    char name[TASK_COMM_LEN];
    int stack_id;
};
BPF_HASH(counts, struct key_t);
BPF_HASH(start, u32);
BPF_STACK_TRACE(stack_traces, STACK_STORAGE_SIZE)

int oncpu(struct pt_regs *ctx, struct task_struct *prev) {
    u32 pid;
    u64 ts, *tsp;

    // record previous thread sleep time
    if (THREAD_FILTER) {
        pid = prev->pid;
        ts = bpf_ktime_get_ns();
        start.update(&pid, &ts);
    }

    // calculate current thread's delta time
    pid = bpf_get_current_pid_tgid();
    tsp = start.lookup(&pid);
    if (tsp == 0)
        return 0;        // missed start or filtered
    u64 delta = bpf_ktime_get_ns() - *tsp;
    start.delete(&pid);
    delta = delta / 1000;
    if (delta < MINBLOCK_US)
        return 0;

    // create map key
    u64 zero = 0, *val;
    struct key_t key = {};

    bpf_get_current_comm(&key.name, sizeof(key.name));
    key.stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);

    val = counts.lookup_or_init(&key, &zero);
    (*val) += delta;
    return 0;
}
"""

# set thread filter
thread_context = ""
if args.pid is not None:
    thread_context = "PID %s" % args.pid
    thread_filter = 'pid == %s' % args.pid
elif args.user_threads_only:
    thread_context = "user threads"
    thread_filter = '!(prev->flags & PF_KTHREAD)'
elif args.kernel_threads_only:
    thread_context = "kernel threads"
    thread_filter = 'prev->flags & PF_KTHREAD'
else:
    thread_context = "all threads"
    thread_filter = '1'
bpf_text = bpf_text.replace('THREAD_FILTER', thread_filter)

# set stack storage size
bpf_text = bpf_text.replace('STACK_STORAGE_SIZE', str(args.stack_storage_size))

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="finish_task_switch", fn_name="oncpu")
matched = b.num_open_kprobes()
if matched == 0:
    print("error: 0 functions traced. Exiting.", file=stderr)
    exit(1)

# header
if not folded:
    print("Tracing off-CPU time (us) of %s by kernel stack" %
        thread_context, end="")
    if duration < 99999999:
        print(" for %d secs." % duration)
    else:
        print("... Hit Ctrl-C to end.")

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
    # handle get_stackid erorrs
    if k.stack_id < 0:
        missing_stacks += 1
        # check for an ENOMEM error
        if k.stack_id == -12:
            has_enomem = True
        continue

    stack = stack_traces.walk(k.stack_id)

    if folded:
        # print folded stack output
        stack = list(stack)[1:]
        line = [k.name.decode()] + [b.ksym(addr) for addr in reversed(stack)]
        print("%s %d" % (";".join(line), v.value))
    else:
        # print default multi-line stack output
        for addr in stack:
            print("    %-16x %s" % (addr, b.ksym(addr)))
        print("    %-16s %s" % ("-", k.name))
        print("        %d\n" % v.value)

if missing_stacks > 0:
    enomem_str = "" if not has_enomem else \
        " Consider increasing --stack-storage-size."
    print("WARNING: %d stack traces could not be displayed.%s" %
        (missing_stacks, enomem_str),
        file=stderr)

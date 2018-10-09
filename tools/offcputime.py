#!/usr/bin/python
#
# offcputime    Summarize off-CPU time by stack trace
#               For Linux, uses BCC, eBPF.
#
# USAGE: offcputime [-h] [-p PID | -u | -k] [-U | -K] [-f] [duration]
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
import errno
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

def stack_id_err(stack_id):
    # -EFAULT in get_stackid normally means the stack-trace is not availible,
    # Such as getting kernel stack trace in userspace code
    return (stack_id < 0) and (stack_id != -errno.EFAULT)

# arguments
examples = """examples:
    ./offcputime             # trace off-CPU stack time until Ctrl-C
    ./offcputime 5           # trace for 5 seconds only
    ./offcputime -f 5        # 5 seconds, and output in folded format
    ./offcputime -m 1000     # trace only events that last more than 1000 usec
    ./offcputime -M 10000    # trace only events that last less than 10000 usec
    ./offcputime -p 185      # only trace threads for PID 185
    ./offcputime -t 188      # only trace thread 188
    ./offcputime -u          # only trace user threads (no kernel)
    ./offcputime -k          # only trace kernel threads (no user)
    ./offcputime -U          # only show user space stacks (no kernel)
    ./offcputime -K          # only show kernel space stacks (no user)
"""
parser = argparse.ArgumentParser(
    description="Summarize off-CPU time by stack trace",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
thread_group = parser.add_mutually_exclusive_group()
# Note: this script provides --pid and --tid flags but their arguments are
# referred to internally using kernel nomenclature: TGID and PID.
thread_group.add_argument("-p", "--pid", metavar="PID", dest="tgid",
    help="trace this PID only", type=positive_int)
thread_group.add_argument("-t", "--tid", metavar="TID", dest="pid",
    help="trace this TID only", type=positive_int)
thread_group.add_argument("-u", "--user-threads-only", action="store_true",
    help="user threads only (no kernel threads)")
thread_group.add_argument("-k", "--kernel-threads-only", action="store_true",
    help="kernel threads only (no user threads)")
stack_group = parser.add_mutually_exclusive_group()
stack_group.add_argument("-U", "--user-stacks-only", action="store_true",
    help="show stacks from user space only (no kernel space stacks)")
stack_group.add_argument("-K", "--kernel-stacks-only", action="store_true",
    help="show stacks from kernel space only (no user space stacks)")
parser.add_argument("-d", "--delimited", action="store_true",
    help="insert delimiter between kernel/user stacks")
parser.add_argument("-f", "--folded", action="store_true",
    help="output folded format")
parser.add_argument("--stack-storage-size", default=1024,
    type=positive_nonzero_int,
    help="the number of unique stack traces that can be stored and "
         "displayed (default 1024)")
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
parser.add_argument("--state", type=positive_int,
    help="filter on this thread state bitmask (eg, 2 == TASK_UNINTERRUPTIBLE" +
         ") see include/linux/sched.h")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
if args.pid and args.tgid:
    parser.error("specify only one of -p and -t")
folded = args.folded
duration = int(args.duration)
debug = 0

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
    u32 pid;
    u32 tgid;
    int user_stack_id;
    int kernel_stack_id;
    char name[TASK_COMM_LEN];
};
BPF_HASH(counts, struct key_t);
BPF_HASH(start, u32);
BPF_STACK_TRACE(stack_traces, STACK_STORAGE_SIZE);

int oncpu(struct pt_regs *ctx, struct task_struct *prev) {
    u32 pid = prev->pid;
    u32 tgid = prev->tgid;
    u64 ts, *tsp;

    // record previous thread sleep time
    if ((THREAD_FILTER) && (STATE_FILTER)) {
        ts = bpf_ktime_get_ns();
        start.update(&pid, &ts);
    }

    // get the current thread's start time
    pid = bpf_get_current_pid_tgid();
    tgid = bpf_get_current_pid_tgid() >> 32;
    tsp = start.lookup(&pid);
    if (tsp == 0) {
        return 0;        // missed start or filtered
    }

    // calculate current thread's delta time
    u64 delta = bpf_ktime_get_ns() - *tsp;
    start.delete(&pid);
    delta = delta / 1000;
    if ((delta < MINBLOCK_US) || (delta > MAXBLOCK_US)) {
        return 0;
    }

    // create map key
    struct key_t key = {};

    key.pid = pid;
    key.tgid = tgid;
    key.user_stack_id = USER_STACK_GET;
    key.kernel_stack_id = KERNEL_STACK_GET;
    bpf_get_current_comm(&key.name, sizeof(key.name));

    counts.increment(key, delta);
    return 0;
}
"""

# set thread filter
thread_context = ""
if args.tgid is not None:
    thread_context = "PID %d" % args.tgid
    thread_filter = 'tgid == %d' % args.tgid
elif args.pid is not None:
    thread_context = "TID %d" % args.pid
    thread_filter = 'pid == %d' % args.pid
elif args.user_threads_only:
    thread_context = "user threads"
    thread_filter = '!(prev->flags & PF_KTHREAD)'
elif args.kernel_threads_only:
    thread_context = "kernel threads"
    thread_filter = 'prev->flags & PF_KTHREAD'
else:
    thread_context = "all threads"
    thread_filter = '1'
if args.state == 0:
    state_filter = 'prev->state == 0'
elif args.state:
    # these states are sometimes bitmask checked
    state_filter = 'prev->state & %d' % args.state
else:
    state_filter = '1'
bpf_text = bpf_text.replace('THREAD_FILTER', thread_filter)
bpf_text = bpf_text.replace('STATE_FILTER', state_filter)

# set stack storage size
bpf_text = bpf_text.replace('STACK_STORAGE_SIZE', str(args.stack_storage_size))
bpf_text = bpf_text.replace('MINBLOCK_US_VALUE', str(args.min_block_time))
bpf_text = bpf_text.replace('MAXBLOCK_US_VALUE', str(args.max_block_time))

# handle stack args
kernel_stack_get = "stack_traces.get_stackid(ctx, 0)"
user_stack_get = "stack_traces.get_stackid(ctx, BPF_F_USER_STACK)"
stack_context = ""
if args.user_stacks_only:
    stack_context = "user"
    kernel_stack_get = "-1"
elif args.kernel_stacks_only:
    stack_context = "kernel"
    user_stack_get = "-1"
else:
    stack_context = "user + kernel"
bpf_text = bpf_text.replace('USER_STACK_GET', user_stack_get)
bpf_text = bpf_text.replace('KERNEL_STACK_GET', kernel_stack_get)

need_delimiter = args.delimited and not (args.kernel_stacks_only or
                                         args.user_stacks_only)

# check for an edge case; the code below will handle this case correctly
# but ultimately nothing will be displayed
if args.kernel_threads_only and args.user_stacks_only:
    print("ERROR: Displaying user stacks for kernel threads " +
          "doesn't make sense.", file=stderr)
    exit(1)

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="finish_task_switch", fn_name="oncpu")
matched = b.num_open_kprobes()
if matched == 0:
    print("error: 0 functions traced. Exiting.", file=stderr)
    exit(1)

# header
if not folded:
    print("Tracing off-CPU time (us) of %s by %s stack" %
        (thread_context, stack_context), end="")
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
    # handle get_stackid errors
    if not args.user_stacks_only and stack_id_err(k.kernel_stack_id):
        missing_stacks += 1
        has_enomem = has_enomem or k.kernel_stack_id == -errno.ENOMEM
    if not args.kernel_stacks_only and stack_id_err(k.user_stack_id):
        missing_stacks += 1
        has_enomem = has_enomem or k.user_stack_id == -errno.ENOMEM

    # user stacks will be symbolized by tgid, not pid, to avoid the overhead
    # of one symbol resolver per thread
    user_stack = [] if k.user_stack_id < 0 else \
        stack_traces.walk(k.user_stack_id)
    kernel_stack = [] if k.kernel_stack_id < 0 else \
        stack_traces.walk(k.kernel_stack_id)

    if folded:
        # print folded stack output
        user_stack = list(user_stack)
        kernel_stack = list(kernel_stack)
        line = [k.name.decode('utf-8', 'replace')]
        # if we failed to get the stack is, such as due to no space (-ENOMEM) or
        # hash collision (-EEXIST), we still print a placeholder for consistency
        if not args.kernel_stacks_only:
            if stack_id_err(k.user_stack_id):
                line.append("[Missed User Stack]")
            else:
                line.extend([b.sym(addr, k.tgid) for addr in reversed(user_stack)])
        if not args.user_stacks_only:
            line.extend(["-"] if (need_delimiter and k.kernel_stack_id >= 0 and k.user_stack_id >= 0) else [])
            if stack_id_err(k.kernel_stack_id):
                line.append("[Missed Kernel Stack]")
            else:
                line.extend([b.ksym(addr) for addr in reversed(kernel_stack)])
        print("%s %d" % (";".join(line), v.value))
    else:
        # print default multi-line stack output
        if not args.user_stacks_only:
            if stack_id_err(k.kernel_stack_id):
                print("    [Missed Kernel Stack]")
            else:
                for addr in kernel_stack:
                    print("    %s" % b.ksym(addr))
        if not args.kernel_stacks_only:
            if need_delimiter and k.user_stack_id >= 0 and k.kernel_stack_id >= 0:
                print("    --")
            if stack_id_err(k.user_stack_id):
                print("    [Missed User Stack]")
            else:
                for addr in user_stack:
                    print("    %s" % b.sym(addr, k.tgid))
        print("    %-16s %s (%d)" % ("-", k.name.decode('utf-8', 'replace'), k.pid))
        print("        %d\n" % v.value)

if missing_stacks > 0:
    enomem_str = "" if not has_enomem else \
        " Consider increasing --stack-storage-size."
    print("WARNING: %d stack traces lost and could not be displayed.%s" %
        (missing_stacks, enomem_str),
        file=stderr)

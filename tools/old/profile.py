#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# profile  Profile CPU usage by sampling stack traces at a timed interval.
#          For Linux, uses BCC, BPF, perf_events. Embedded C.
#
# This is an efficient profiler, as stack traces are frequency counted in
# kernel context, rather than passing every stack to user space for frequency
# counting there. Only the unique stacks and counts are passed to user space
# at the end of the profile, greatly reducing the kernel<->user transfer.
#
# This uses perf_event_open to setup a timer which is instrumented by BPF,
# and for efficiency it does not initialize the perf ring buffer, so the
# redundant perf samples are not collected.
#
# Kernel stacks are post-process in user-land to skip the interrupt framework
# frames. You can improve efficiency a little by specifying the exact number
# of frames to skip with -s, provided you know what that is. If you get -s
# wrong, note that the first line is the IP, and then the (skipped) stack.
#
# Note: if another perf-based sampling session is active, the output may become
# polluted with their events. On older kernels, the ouptut may also become
# polluted with tracing sessions (when the kprobe is used instead of the
# tracepoint). If this becomes a problem, logic can be added to filter events.
#
# REQUIRES: Linux 4.6+ (BPF_MAP_TYPE_STACK_TRACE support), and the
# perf_misc_flags() function symbol to exist. The latter may or may not
# exist depending on your kernel build. Linux 4.9 provides a proper solution
# to this (this tool will be updated).
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# THANKS: Sasha Goldshtein, Andrew Birchall, and Evgeny Vereshchagin, who wrote
# much of the code here, borrowed from tracepoint.py and offcputime.py.
#
# 15-Jul-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF, Perf
from sys import stderr
from time import sleep
import argparse
import signal
import os
import errno
import multiprocessing
import ctypes as ct

#
# Process Arguments
#

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
    ./profile             # profile stack traces at 49 Hertz until Ctrl-C
    ./profile -F 99       # profile stack traces at 99 Hertz
    ./profile 5           # profile at 49 Hertz for 5 seconds only
    ./profile -f 5        # output in folded format for flame graphs
    ./profile -p 185      # only profile threads for PID 185
    ./profile -U          # only show user space stacks (no kernel)
    ./profile -K          # only show kernel space stacks (no user)
    ./profile -S 11       # always skip 11 frames of kernel stack
"""
parser = argparse.ArgumentParser(
    description="Profile CPU stack traces at a timed interval",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
thread_group = parser.add_mutually_exclusive_group()
thread_group.add_argument("-p", "--pid", type=positive_int,
    help="profile this PID only")
# TODO: add options for user/kernel threads only
stack_group = parser.add_mutually_exclusive_group()
stack_group.add_argument("-U", "--user-stacks-only", action="store_true",
    help="show stacks from user space only (no kernel space stacks)")
stack_group.add_argument("-K", "--kernel-stacks-only", action="store_true",
    help="show stacks from kernel space only (no user space stacks)")
parser.add_argument("-F", "--frequency", type=positive_int, default=49,
    help="sample frequency, Hertz (default 49)")
parser.add_argument("-d", "--delimited", action="store_true",
    help="insert delimiter between kernel/user stacks")
parser.add_argument("-a", "--annotations", action="store_true",
    help="add _[k] annotations to kernel frames")
parser.add_argument("-f", "--folded", action="store_true",
    help="output folded format, one line per stack (for flame graphs)")
parser.add_argument("--stack-storage-size", default=2048,
    type=positive_nonzero_int,
    help="the number of unique stack traces that can be stored and "
        "displayed (default 2048)")
parser.add_argument("-S", "--kernel-skip", type=positive_int, default=0,
    help="skip this many kernel frames (default 3)")
parser.add_argument("duration", nargs="?", default=99999999,
    type=positive_nonzero_int,
    help="duration of trace, in seconds")

# option logic
args = parser.parse_args()
skip = args.kernel_skip
pid = int(args.pid) if args.pid is not None else -1
duration = int(args.duration)
debug = 0
need_delimiter = args.delimited and not (args.kernel_stacks_only or
    args.user_stacks_only)
# TODO: add stack depth, and interval

#
# Setup BPF
#

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct key_t {
    u32 pid;
    u64 kernel_ip;
    u64 kernel_ret_ip;
    int user_stack_id;
    int kernel_stack_id;
    char name[TASK_COMM_LEN];
};
BPF_HASH(counts, struct key_t);
BPF_HASH(start, u32);
BPF_STACK_TRACE(stack_traces, STACK_STORAGE_SIZE);

// This code gets a bit complex. Probably not suitable for casual hacking.

PERF_TRACE_EVENT {
    u32 pid = bpf_get_current_pid_tgid();
    if (!(THREAD_FILTER))
        return 0;

    // create map key
    u64 zero = 0, *val;
    struct key_t key = {.pid = pid};
    bpf_get_current_comm(&key.name, sizeof(key.name));

    // get stacks
    key.user_stack_id = USER_STACK_GET;
    key.kernel_stack_id = KERNEL_STACK_GET;

    if (key.kernel_stack_id >= 0) {
        // populate extras to fix the kernel stack
        struct pt_regs regs = {};
        bpf_probe_read(&regs, sizeof(regs), (void *)REGS_LOCATION);
        u64 ip = PT_REGS_IP(&regs);

        // if ip isn't sane, leave key ips as zero for later checking
#ifdef CONFIG_RANDOMIZE_MEMORY
        if (ip > __PAGE_OFFSET_BASE) {
#else
        if (ip > PAGE_OFFSET) {
#endif
            key.kernel_ip = ip;
            if (DO_KERNEL_RIP) {
                /*
                 * User didn't specify a skip value (-s), so we will figure
                 * out how many interrupt framework frames to skip by recording
                 * the kernel rip, then later scanning for it on the stack.
                 * This is likely x86_64 specific; can use -s as a workaround
                 * until this supports your architecture.
                 */
                bpf_probe_read(&key.kernel_ret_ip, sizeof(key.kernel_ret_ip),
                (void *)(regs.bp + 8));
            }
        }
    }

    val = counts.lookup_or_init(&key, &zero);
    (*val)++;
    return 0;
}
"""

# set thread filter
thread_context = ""
perf_filter = "-a"
if args.pid is not None:
    thread_context = "PID %s" % args.pid
    thread_filter = 'pid == %s' % args.pid
    perf_filter = '-p %s' % args.pid
else:
    thread_context = "all threads"
    thread_filter = '1'
bpf_text = bpf_text.replace('THREAD_FILTER', thread_filter)

# set stack storage size
bpf_text = bpf_text.replace('STACK_STORAGE_SIZE', str(args.stack_storage_size))

# handle stack args
kernel_stack_get = "stack_traces.get_stackid(args, " \
    "%d | BPF_F_REUSE_STACKID)" % skip
user_stack_get = \
    "stack_traces.get_stackid(args, BPF_F_REUSE_STACKID | BPF_F_USER_STACK)"
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
if skip:
    # don't record the rip, as we won't use it
    bpf_text = bpf_text.replace('DO_KERNEL_RIP', '0')
else:
    # rip is used to skip interrupt infrastructure frames
    bpf_text = bpf_text.replace('DO_KERNEL_RIP', '1')

# header
if not args.folded:
    print("Sampling at %d Hertz of %s by %s stack" %
        (args.frequency, thread_context, stack_context), end="")
    if duration < 99999999:
        print(" for %d secs." % duration)
    else:
        print("... Hit Ctrl-C to end.")

# kprobe perf_misc_flags()
bpf_text = bpf_text.replace('PERF_TRACE_EVENT',
    'int kprobe__perf_misc_flags(struct pt_regs *args)')
bpf_text = bpf_text.replace('REGS_LOCATION', 'PT_REGS_PARM1(args)')
if debug:
    print(bpf_text)

# initialize BPF
try:
    b = BPF(text=bpf_text)
except:
    print("BPF initialization failed. perf_misc_flags() may be inlined in " +
        "your kernel build.\nThis tool will be updated in the future to " +
        "support Linux 4.9, which has reliable profiling support. Exiting.")
    exit()

# signal handler
def signal_ignore(signal, frame):
    print()

#
# Setup perf_events
#

# use perf_events to sample
try:
    Perf.perf_event_open(0, pid=-1, ptype=Perf.PERF_TYPE_SOFTWARE,
        freq=args.frequency)
except:
    print("ERROR: initializing perf_events for sampling.\n"
        "To debug this, try running the following command:\n"
        "    perf record -F 49 -e cpu-clock %s -- sleep 1\n"
        "If that also doesn't work, fix it first." % perf_filter, file=stderr)
    exit(0)

#
# Output Report
#

# collect samples
try:
    sleep(duration)
except KeyboardInterrupt:
    # as cleanup can take some time, trap Ctrl-C:
    signal.signal(signal.SIGINT, signal_ignore)

if not args.folded:
    print()

def aksym(addr):
    if args.annotations:
        return b.ksym(addr) + "_[k]"
    else:
        return b.ksym(addr)

# output stacks
missing_stacks = 0
has_enomem = False
counts = b.get_table("counts")
stack_traces = b.get_table("stack_traces")
for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    # handle get_stackid erorrs
    if (not args.user_stacks_only and k.kernel_stack_id < 0 and
            k.kernel_stack_id != -errno.EFAULT) or \
            (not args.kernel_stacks_only and k.user_stack_id < 0 and
            k.user_stack_id != -errno.EFAULT):
        missing_stacks += 1
        # check for an ENOMEM error
        if k.kernel_stack_id == -errno.ENOMEM or \
                k.user_stack_id == -errno.ENOMEM:
            has_enomem = True

    user_stack = [] if k.user_stack_id < 0 else \
        stack_traces.walk(k.user_stack_id)
    kernel_tmp = [] if k.kernel_stack_id < 0 else \
        stack_traces.walk(k.kernel_stack_id)

    # fix kernel stack
    kernel_stack = []
    if k.kernel_stack_id >= 0:
        if skip:
            # fixed skip
            for addr in kernel_tmp:
                kernel_stack.append(addr)
            kernel_stack = kernel_stack[skip:]
        else:
            # skip the interrupt framework stack by searching for our RIP
            skipping = 1
            for addr in kernel_tmp:
                if k.kernel_ret_ip == addr:
                    skipping = 0
                if not skipping:
                    kernel_stack.append(addr)
        if k.kernel_ip:
            kernel_stack.insert(0, k.kernel_ip)

    do_delimiter = need_delimiter and kernel_stack

    if args.folded:
        # print folded stack output
        user_stack = list(user_stack)
        kernel_stack = list(kernel_stack)
        line = [k.name.decode('utf-8', 'replace')] + \
            [b.sym(addr, k.pid) for addr in reversed(user_stack)] + \
            (do_delimiter and ["-"] or []) + \
            [aksym(addr) for addr in reversed(kernel_stack)]
        print("%s %d" % (";".join(line), v.value))
    else:
        # print default multi-line stack output.
        for addr in kernel_stack:
            print("    %s" % aksym(addr))
        if do_delimiter:
            print("    --")
        for addr in user_stack:
            print("    %s" % b.sym(addr, k.pid))
        print("    %-16s %s (%d)" % ("-", k.name, k.pid))
        print("        %d\n" % v.value)

# check missing
if missing_stacks > 0:
    enomem_str = "" if not has_enomem else \
        " Consider increasing --stack-storage-size."
    print("WARNING: %d stack traces could not be displayed.%s" %
        (missing_stacks, enomem_str),
        file=stderr)

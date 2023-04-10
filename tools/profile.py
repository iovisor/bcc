#!/usr/bin/env python
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
# By default CPU idle stacks are excluded by simply excluding PID 0.
#
# REQUIRES: Linux 4.9+ (BPF_PROG_TYPE_PERF_EVENT support). Under tools/old is
# a version of this tool that may work on Linux 4.6 - 4.8.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# THANKS: Alexei Starovoitov, who added proper BPF profiling support to Linux;
# Sasha Goldshtein, Andrew Birchall, and Evgeny Vereshchagin, who wrote much
# of the code here, borrowed from tracepoint.py and offcputime.py; and
# Teng Qin, who added perf support in bcc.
#
# 15-Jul-2016   Brendan Gregg   Created this.
# 20-Oct-2016      "      "     Switched to use the new 4.9 support.
# 26-Jan-2019      "      "     Changed to exclude CPU idle by default.
# 11-Apr-2023   Rocky Xing      Added option to increase hash storage size.

from __future__ import print_function
from bcc import BPF, PerfType, PerfSWConfig
from bcc.containers import filter_by_containers
from sys import stderr
from time import sleep
import argparse
import signal
import os
import errno

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

def positive_int_list(val):
    vlist = val.split(",")
    if len(vlist) <= 0:
        raise argparse.ArgumentTypeError("must be an integer list")

    return [positive_int(v) for v in vlist]

def positive_nonzero_int(val):
    ival = positive_int(val)
    if ival == 0:
        raise argparse.ArgumentTypeError("must be nonzero")
    return ival

def stack_id_err(stack_id):
    # -EFAULT in get_stackid normally means the stack-trace is not available,
    # Such as getting kernel stack trace in userspace code
    return (stack_id < 0) and (stack_id != -errno.EFAULT)

# arguments
examples = """examples:
    ./profile             # profile stack traces at 49 Hertz until Ctrl-C
    ./profile -F 99       # profile stack traces at 99 Hertz
    ./profile -c 1000000  # profile stack traces every 1 in a million events
    ./profile 5           # profile at 49 Hertz for 5 seconds only
    ./profile -f 5        # output in folded format for flame graphs
    ./profile -p 185      # only profile process with PID 185
    ./profile -L 185      # only profile thread with TID 185
    ./profile -U          # only show user space stacks (no kernel)
    ./profile -K          # only show kernel space stacks (no user)
    ./profile --cgroupmap mappath  # only trace cgroups in this BPF map
    ./profile --mntnsmap mappath   # only trace mount namespaces in the map
"""
parser = argparse.ArgumentParser(
    description="Profile CPU stack traces at a timed interval",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
thread_group = parser.add_mutually_exclusive_group()
thread_group.add_argument("-p", "--pid", type=positive_int_list,
    help="profile process with one or more comma separated PIDs only")
thread_group.add_argument("-L", "--tid", type=positive_int_list,
    help="profile thread with one or more comma separated TIDs only")
# TODO: add options for user/kernel threads only
stack_group = parser.add_mutually_exclusive_group()
stack_group.add_argument("-U", "--user-stacks-only", action="store_true",
    help="show stacks from user space only (no kernel space stacks)")
stack_group.add_argument("-K", "--kernel-stacks-only", action="store_true",
    help="show stacks from kernel space only (no user space stacks)")
sample_group = parser.add_mutually_exclusive_group()
sample_group.add_argument("-F", "--frequency", type=positive_int,
    help="sample frequency, Hertz")
sample_group.add_argument("-c", "--count", type=positive_int,
    help="sample period, number of events")
parser.add_argument("-d", "--delimited", action="store_true",
    help="insert delimiter between kernel/user stacks")
parser.add_argument("-a", "--annotations", action="store_true",
    help="add _[k] annotations to kernel frames")
parser.add_argument("-I", "--include-idle", action="store_true",
    help="include CPU idle stacks")
parser.add_argument("-f", "--folded", action="store_true",
    help="output folded format, one line per stack (for flame graphs)")
parser.add_argument("--hash-storage-size", default=40960,
    type=positive_nonzero_int,
    help="the number of hash keys that can be stored and (default %(default)s)")
parser.add_argument("--stack-storage-size", default=16384,
    type=positive_nonzero_int,
    help="the number of unique stack traces that can be stored and "
        "displayed (default %(default)s)")
parser.add_argument("duration", nargs="?", default=99999999,
    type=positive_nonzero_int,
    help="duration of trace, in seconds")
parser.add_argument("-C", "--cpu", type=int, default=-1,
    help="cpu number to run profile on")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
parser.add_argument("--cgroupmap",
    help="trace cgroups in this BPF map only")
parser.add_argument("--mntnsmap",
    help="trace mount namespaces in this BPF map only")

# option logic
args = parser.parse_args()
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
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>

struct key_t {
    u32 pid;
    u64 kernel_ip;
    int user_stack_id;
    int kernel_stack_id;
    char name[TASK_COMM_LEN];
};
BPF_HASH(counts, struct key_t, u64, HASH_STORAGE_SIZE);
BPF_STACK_TRACE(stack_traces, STACK_STORAGE_SIZE);

// This code gets a bit complex. Probably not suitable for casual hacking.

int do_perf_event(struct bpf_perf_event_data *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id;

    if (IDLE_FILTER)
        return 0;

    if (!(THREAD_FILTER))
        return 0;

    if (container_should_be_filtered()) {
        return 0;
    }

    // create map key
    struct key_t key = {.pid = tgid};
    bpf_get_current_comm(&key.name, sizeof(key.name));

    // get stacks
    key.user_stack_id = USER_STACK_GET;
    key.kernel_stack_id = KERNEL_STACK_GET;

    if (key.kernel_stack_id >= 0) {
        // populate extras to fix the kernel stack
        u64 ip = PT_REGS_IP(&ctx->regs);
        u64 page_offset;

        // if ip isn't sane, leave key ips as zero for later checking
#if defined(CONFIG_X86_64) && defined(__PAGE_OFFSET_BASE)
        // x64, 4.16, ..., 4.11, etc., but some earlier kernel didn't have it
        page_offset = __PAGE_OFFSET_BASE;
#elif defined(CONFIG_X86_64) && defined(__PAGE_OFFSET_BASE_L4)
        // x64, 4.17, and later
#if defined(CONFIG_DYNAMIC_MEMORY_LAYOUT) && defined(CONFIG_X86_5LEVEL)
        page_offset = __PAGE_OFFSET_BASE_L5;
#else
        page_offset = __PAGE_OFFSET_BASE_L4;
#endif
#else
        // earlier x86_64 kernels, e.g., 4.6, comes here
        // arm64, s390, powerpc, x86_32
        page_offset = PAGE_OFFSET;
#endif

        if (ip > page_offset) {
            key.kernel_ip = ip;
        }
    }

    counts.increment(key);
    return 0;
}
"""

# set idle filter
idle_filter = "pid == 0"
if args.include_idle:
    idle_filter = "0"
bpf_text = bpf_text.replace('IDLE_FILTER', idle_filter)

# set process/thread filter
thread_context = ""
thread_filter = ""
if args.pid is not None:
    thread_context = "PID %s" % args.pid
    thread_filter = " || ".join("tgid == " + str(pid) for pid in args.pid)
elif args.tid is not None:
    thread_context = "TID %s" % args.tid
    thread_filter = " || ".join("pid == " + str(tid) for tid in args.tid)
else:
    thread_context = "all threads"
    thread_filter = '1'
bpf_text = bpf_text.replace('THREAD_FILTER', thread_filter)

# set stack storage size
bpf_text = bpf_text.replace('HASH_STORAGE_SIZE', str(args.hash_storage_size))
bpf_text = bpf_text.replace('STACK_STORAGE_SIZE', str(args.stack_storage_size))

# handle stack args
kernel_stack_get = "stack_traces.get_stackid(&ctx->regs, 0)"
user_stack_get = "stack_traces.get_stackid(&ctx->regs, BPF_F_USER_STACK)"
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
bpf_text = filter_by_containers(args) + bpf_text

sample_freq = 0
sample_period = 0
if args.frequency:
    sample_freq = args.frequency
elif args.count:
    sample_period = args.count
else:
    # If user didn't specify anything, use default 49Hz sampling
    sample_freq = 49
sample_context = "%s%d %s" % (("", sample_freq, "Hertz") if sample_freq
                         else ("every ", sample_period, "events"))

# header
if not args.folded:
    print("Sampling at %s of %s by %s stack" %
        (sample_context, thread_context, stack_context), end="")
    if args.cpu >= 0:
        print(" on CPU#{}".format(args.cpu), end="")
    if duration < 99999999:
        print(" for %d secs." % duration)
    else:
        print("... Hit Ctrl-C to end.")

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF & perf_events
b = BPF(text=bpf_text)
b.attach_perf_event(ev_type=PerfType.SOFTWARE,
    ev_config=PerfSWConfig.CPU_CLOCK, fn_name="do_perf_event",
    sample_period=sample_period, sample_freq=sample_freq, cpu=args.cpu)

# signal handler
def signal_ignore(signal, frame):
    print()

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
        return b.ksym(addr) + "_[k]".encode()
    else:
        return b.ksym(addr)

# output stacks
missing_stacks = 0
has_collision = False
counts = b.get_table("counts")
htab_full = args.hash_storage_size == len(counts)
stack_traces = b.get_table("stack_traces")
for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    # handle get_stackid errors
    if not args.user_stacks_only and stack_id_err(k.kernel_stack_id):
        missing_stacks += 1
        # hash collision (-EEXIST) suggests that the map size may be too small
        has_collision = has_collision or k.kernel_stack_id == -errno.EEXIST
    if not args.kernel_stacks_only and stack_id_err(k.user_stack_id):
        missing_stacks += 1
        has_collision = has_collision or k.user_stack_id == -errno.EEXIST

    user_stack = [] if k.user_stack_id < 0 else \
        stack_traces.walk(k.user_stack_id)
    kernel_tmp = [] if k.kernel_stack_id < 0 else \
        stack_traces.walk(k.kernel_stack_id)

    # fix kernel stack
    kernel_stack = []
    if k.kernel_stack_id >= 0:
        for addr in kernel_tmp:
            kernel_stack.append(addr)
        # the later IP checking
        if k.kernel_ip:
            kernel_stack.insert(0, k.kernel_ip)

    if args.folded:
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
                line.extend([b.sym(addr, k.pid).decode('utf-8', 'replace') for addr in reversed(user_stack)])
        if not args.user_stacks_only:
            line.extend(["-"] if (need_delimiter and k.kernel_stack_id >= 0 and k.user_stack_id >= 0) else [])
            if stack_id_err(k.kernel_stack_id):
                line.append("[Missed Kernel Stack]")
            else:
                line.extend([aksym(addr).decode('utf-8', 'replace') for addr in reversed(kernel_stack)])
        print("%s %d" % (";".join(line), v.value))
    else:
        # print default multi-line stack output
        if not args.user_stacks_only:
            if stack_id_err(k.kernel_stack_id):
                print("    [Missed Kernel Stack]")
            else:
                for addr in kernel_stack:
                    print("    %s" % aksym(addr).decode('utf-8', 'replace'))
        if not args.kernel_stacks_only:
            if need_delimiter and k.user_stack_id >= 0 and k.kernel_stack_id >= 0:
                print("    --")
            if stack_id_err(k.user_stack_id):
                print("    [Missed User Stack]")
            else:
                for addr in user_stack:
                    print("    %s" % b.sym(addr, k.pid).decode('utf-8', 'replace'))
        print("    %-16s %s (%d)" % ("-", k.name.decode('utf-8', 'replace'), k.pid))
        print("        %d\n" % v.value)

# check missing
if missing_stacks > 0:
    enomem_str = "" if not has_collision else \
        " Consider increasing --stack-storage-size."
    print("WARNING: %d stack traces could not be displayed.%s" %
        (missing_stacks, enomem_str),
        file=stderr)

# check whether hash table is full
if htab_full:
    print("WARNING: hash table full. Consider increasing --hash-storage-size.",
        file=stderr)

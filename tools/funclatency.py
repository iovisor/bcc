#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# funclatency   Time kernel funcitons and print latency as a histogram.
#               For Linux, uses BCC, eBPF.
#
# USAGE: funclatency [-h] [-p PID] [-i INTERVAL] [-T] [-u] [-m] [-r] pattern
#
# Run "funclatency -h" for full usage.
#
# The pattern is a string with optional '*' wildcards, similar to file globbing.
# If you'd prefer to use regular expressions, use the -r option. Matching
# multiple functions is of limited use, since the output has one histogram for
# everything. Future versions should split the output histogram by the function.
#
# Currently nested or recursive functions are not supported properly, and
# timestamps will be overwritten, creating dubious output. Try to match single
# functions, or groups of functions that run at the same stack layer, and
# don't ultimately call each other.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 20-Sep-2015   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import signal

# arguments
examples = """examples:
    ./funclatency do_sys_open       # time the do_sys_open() kenel function
    ./funclatency -u vfs_read       # time vfs_read(), in microseconds
    ./funclatency -m do_nanosleep   # time do_nanosleep(), in milliseconds
    ./funclatency -mTi 5 vfs_read   # output every 5 seconds, with timestamps
    ./funclatency -p 181 vfs_read   # time process 181 only
    ./funclatency 'vfs_fstat*'      # time both vfs_fstat() and vfs_fstatat()
    ./funclatency -F 'vfs_r*'       # show one histogram per matched function
"""
parser = argparse.ArgumentParser(
    description="Time kernel funcitons and print latency as a histogram",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-i", "--interval", default=99999999,
    help="summary interval, seconds")
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-u", "--microseconds", action="store_true",
    help="microsecond histogram")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="millisecond histogram")
parser.add_argument("-F", "--function", action="store_true",
    help="show a separate histogram per function")
parser.add_argument("-r", "--regexp", action="store_true",
    help="use regular expressions. Default is \"*\" wildcards only.")
parser.add_argument("pattern",
    help="search expression for kernel functions")
args = parser.parse_args()
pattern = args.pattern
if not args.regexp:
    pattern = pattern.replace('*', '.*')
    pattern = '^' + pattern + '$'
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

typedef struct ip_key {
    u64 ip;
    u64 slot;
} ip_key_t;

BPF_HASH(start, u32);
STORAGE

int trace_func_entry(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    FILTER
    ENTRYSTORE
    start.update(&pid, &ts);

    return 0;
}

int trace_func_return(struct pt_regs *ctx)
{
    u64 *tsp, delta;
    u32 pid = bpf_get_current_pid_tgid();

    // calculate delta time
    tsp = start.lookup(&pid);
    if (tsp == 0) {
        return 0;   // missed start
    }
    delta = bpf_ktime_get_ns() - *tsp;
    start.delete(&pid);
    FACTOR

    // store as histogram
    STORE

    return 0;
}
"""

# code substitutions
if args.pid:
    bpf_text = bpf_text.replace('FILTER',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '')
if args.milliseconds:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000000;')
    label = "msecs"
elif args.microseconds:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000;')
    label = "usecs"
else:
    bpf_text = bpf_text.replace('FACTOR', '')
    label = "nsecs"
if args.function:
    bpf_text = bpf_text.replace('STORAGE', 'BPF_HASH(ipaddr, u32);\n' +
        'BPF_HISTOGRAM(dist, ip_key_t);')
    # stash the IP on entry, as on return it's kretprobe_trampoline:
    bpf_text = bpf_text.replace('ENTRYSTORE',
        'u64 ip = PT_REGS_IP(ctx); ipaddr.update(&pid, &ip);')
    bpf_text = bpf_text.replace('STORE',
        'u64 ip, *ipp = ipaddr.lookup(&pid); if (ipp) { ip = *ipp; ' +
        'dist.increment((ip_key_t){ip, bpf_log2l(delta)}); ' +
        'ipaddr.delete(&pid); }')
else:
    bpf_text = bpf_text.replace('STORAGE', 'BPF_HISTOGRAM(dist);')
    bpf_text = bpf_text.replace('ENTRYSTORE', '')
    bpf_text = bpf_text.replace('STORE',
        'dist.increment(bpf_log2l(delta));')
if debug:
    print(bpf_text)

# signal handler
def signal_ignore(signal, frame):
    print()

# load BPF program
b = BPF(text=bpf_text)
b.attach_kprobe(event_re=pattern, fn_name="trace_func_entry")
b.attach_kretprobe(event_re=pattern, fn_name="trace_func_return")
matched = b.num_open_kprobes()
if matched == 0:
    print("0 functions matched by \"%s\". Exiting." % args.pattern)
    exit()

# header
print("Tracing %d functions for \"%s\"... Hit Ctrl-C to end." %
    (matched / 2, args.pattern))

# output
exiting = 0 if args.interval else 1
dist = b.get_table("dist")
while (1):
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = 1
        # as cleanup can take many seconds, trap Ctrl-C:
        signal.signal(signal.SIGINT, signal_ignore)

    print()
    if args.timestamp:
        print("%-8s\n" % strftime("%H:%M:%S"), end="")

    if args.function:
        dist.print_log2_hist(label, "Function", BPF.ksym)
    else:
        dist.print_log2_hist(label)
    dist.clear()

    if exiting:
        print("Detaching...")
        exit()

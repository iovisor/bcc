#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# funcinterval   Time interval between the same function, tracepoint
#                as a histogram.
#
# USAGE: funcinterval [-h] [-p PID] [-i INTERVAL] [-T] [-u] [-m] [-v] pattern
#
# Run "funcinterval -h" for full usage.
#
# Copyright (c) 2020 Realtek, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 03-Jun-2020   Edward Wu   Referenced funclatency and created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import signal

# arguments
examples = """examples:
    # time the interval of do_sys_open()
    ./funcinterval do_sys_open
    # time the interval of xhci_ring_ep_doorbell(), in microseconds
    ./funcinterval -u xhci_ring_ep_doorbell
    # time the interval of do_nanosleep(), in milliseconds
    ./funcinterval -m do_nanosleep
    # output every 5 seconds, with timestamps
    ./funcinterval -mTi 5 vfs_read
    # time process 181 only
    ./funcinterval -p 181 vfs_read
    # time the interval of mm_vmscan_direct_reclaim_begin tracepoint
    ./funcinterval t:vmscan:mm_vmscan_direct_reclaim_begin
"""
parser = argparse.ArgumentParser(
    description="Time interval and print latency as a histogram",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", type=int,
    help="trace this PID only")
parser.add_argument("-i", "--interval", type=int,
    help="summary interval, in seconds")
parser.add_argument("-d", "--duration", type=int,
    help="total duration of trace, in seconds")
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-u", "--microseconds", action="store_true",
    help="microsecond histogram")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="millisecond histogram")
parser.add_argument("-v", "--verbose", action="store_true",
    help="print the BPF program (for debugging purposes)")
parser.add_argument("pattern",
    help="Function/Tracepoint name for tracing")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
if args.duration and not args.interval:
    args.interval = args.duration
if not args.interval:
    args.interval = 99999999

def bail(error):
    print("Error: " + error)
    exit(1)


parts = args.pattern.split(':')
if len(parts) == 1:
    attach_type = "function"
    pattern = args.pattern
elif len(parts) == 3:
    attach_type = "tracepoint"
    pattern = ':'.join(parts[1:])
else:
    bail("unrecognized pattern format '%s'" % pattern)

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

BPF_HASH(start, u32, u64, 1);
BPF_HISTOGRAM(dist);

int trace_func_entry(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 index = 0, tgid = pid_tgid >> 32;
    u64 *tsp, ts = bpf_ktime_get_ns(), delta;

    FILTER
    tsp = start.lookup(&index);
    if (tsp == 0)
        goto out;

    delta = ts - *tsp;
    FACTOR

    // store as histogram
    dist.increment(bpf_log2l(delta));

out:
    start.update(&index, &ts);

    return 0;
}
"""

# code substitutions
if args.pid:
    bpf_text = bpf_text.replace('FILTER',
        'if (tgid != %d) { return 0; }' % args.pid)
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

if args.verbose or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# signal handler
def signal_ignore(signal, frame):
    print()


# load BPF program
b = BPF(text=bpf_text)

if len(parts) == 1:
    b.attach_kprobe(event=pattern, fn_name="trace_func_entry")
    matched = b.num_open_kprobes()
elif len(parts) == 3:
    b.attach_tracepoint(tp=pattern, fn_name="trace_func_entry")
    matched = b.num_open_tracepoints()

if matched == 0:
    print("0 %s matched by \"%s\". Exiting." % (attach_type, pattern))
    exit()

# header
print("Tracing %s for \"%s\"... Hit Ctrl-C to end." %
    (attach_type, pattern))

exiting = 0 if args.interval else 1
seconds = 0
dist = b.get_table("dist")
start = b.get_table("start")
while (1):
    try:
        sleep(args.interval)
        seconds += args.interval
    except KeyboardInterrupt:
        exiting = 1
        # as cleanup can take many seconds, trap Ctrl-C:
        signal.signal(signal.SIGINT, signal_ignore)
    if args.duration and seconds >= args.duration:
        exiting = 1

    print()
    if args.timestamp:
        print("%-8s\n" % strftime("%H:%M:%S"), end="")

    dist.print_log2_hist(label)
    dist.clear()
    start.clear()

    if exiting:
        print("Detaching...")
        exit()

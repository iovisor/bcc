#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# funccount Count kernel function calls.
#           For Linux, uses BCC, eBPF. See .c file.
#
# USAGE: funccount [-h] [-p PID] [-i INTERVAL] [-T] [-r] pattern
#
# The pattern is a string with optional '*' wildcards, similar to file globbing.
# If you'd prefer to use regular expressions, use the -r option.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 09-Sep-2015   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import signal

# arguments
examples = """examples:
    ./funccount 'vfs_*'         # count kernel functions starting with "vfs"
    ./funccount 'tcp_send*'     # count kernel funcs starting with "tcp_send"
    ./funccount -r '^vfs.*'     # same as above, using regular expressions
    ./funccount -Ti 5 'vfs_*'   # output every 5 seconds, with timestamps
    ./funccount -p 185 'vfs_*'  # count vfs calls for PID 181 only
"""
parser = argparse.ArgumentParser(
    description="Count kernel function calls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-i", "--interval", default=99999999,
    help="summary interval, seconds")
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
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

# signal handler
def signal_ignore(signal, frame):
    print()

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

struct key_t {
    u64 ip;
};
BPF_HASH(counts, struct key_t);

int trace_count(struct pt_regs *ctx) {
    FILTER
    struct key_t key = {};
    u64 *val;
    // the kprobe pc is slightly after the function starting address, align
    // back to the start (4 byte alignment) in order to match /proc/kallsyms
    key.ip = PT_REGS_IP(ctx) & ~3ull;
    val = counts.lookup(&key);
    if (!val)
        return 0;
    (*val)++;
    return 0;
}
"""
if args.pid:
    bpf_text = bpf_text.replace('FILTER',
        ('u32 pid; pid = bpf_get_current_pid_tgid(); ' +
        'if (pid != %s) { return 0; }') % (args.pid))
else:
    bpf_text = bpf_text.replace('FILTER', '')
if debug:
    print(bpf_text)
b = BPF(text=bpf_text)
counts = b.get_table("counts")

# pre-insert the function addresses into the counts table
fns = b._get_kprobe_functions(pattern)
for fn in fns:
    addr = b.ksymname(fn)
    if addr == -1:
        raise Exception("Unknown symbol name %s" % fn)
    counts[counts.Key(addr)] = counts.Leaf()

b.attach_kprobe(event_re=pattern, fn_name="trace_count")
matched = b.num_open_kprobes()
if matched == 0:
    print("0 functions matched by \"%s\". Exiting." % args.pattern)
    exit()

# header
print("Tracing %d functions for \"%s\"... Hit Ctrl-C to end." %
    (matched, args.pattern))

# output
exiting = 0 if args.interval else 1
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

    print("%-16s %-26s %8s" % ("ADDR", "FUNC", "COUNT"))
    for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
        if v.value == 0: continue
        print("%-16x %-26s %8d" % (k.ip, b.ksym(k.ip), v.value))
    counts.zero()

    if exiting:
        print("Detaching...")
        exit()

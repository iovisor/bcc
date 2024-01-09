#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# vfsstat   Count some VFS calls.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of counting multiple events as a stat tool.
#
# USAGE: vfsstat [-h] [-p PID] [interval] [count]
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Aug-2015   Brendan Gregg   Created this.
# 12-Oct-2022   Rocky Xing      Added PID filter support.

from __future__ import print_function
from bcc import BPF
from ctypes import c_int
from time import sleep, strftime
from sys import argv
import argparse

# arguments
examples = """examples:
    ./vfsstat             # count some VFS calls per second
    ./vfsstat -p 185      # trace PID 185 only
    ./vfsstat 2 5         # print 2 second summaries, 5 times
"""
parser = argparse.ArgumentParser(
    description="Count some VFS calls.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("interval", nargs="?", default=1,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)

args = parser.parse_args()
countdown = int(args.count)
debug = 0

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

enum stat_types {
    S_READ = 1,
    S_WRITE,
    S_FSYNC,
    S_OPEN,
    S_CREATE,
    S_MAXSTAT
};

BPF_ARRAY(stats, u64, S_MAXSTAT);

static void stats_try_increment(int key) {
    PID_FILTER
    stats.atomic_increment(key);
}
"""

bpf_text_kprobe = """
void do_read(struct pt_regs *ctx) { stats_try_increment(S_READ); }
void do_write(struct pt_regs *ctx) { stats_try_increment(S_WRITE); }
void do_fsync(struct pt_regs *ctx) { stats_try_increment(S_FSYNC); }
void do_open(struct pt_regs *ctx) { stats_try_increment(S_OPEN); }
void do_create(struct pt_regs *ctx) { stats_try_increment(S_CREATE); }
"""

bpf_text_kfunc = """
KFUNC_PROBE(vfs_read)         { stats_try_increment(S_READ); return 0; }
KFUNC_PROBE(vfs_write)        { stats_try_increment(S_WRITE); return 0; }
KFUNC_PROBE(vfs_fsync_range)  { stats_try_increment(S_FSYNC); return 0; }
KFUNC_PROBE(vfs_open)         { stats_try_increment(S_OPEN); return 0; }
KFUNC_PROBE(vfs_create)       { stats_try_increment(S_CREATE); return 0; }
"""

is_support_kfunc = BPF.support_kfunc()
if is_support_kfunc:
    bpf_text += bpf_text_kfunc
else:
    bpf_text += bpf_text_kprobe

if args.pid:
    bpf_text = bpf_text.replace('PID_FILTER', """
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != %s) {
        return;
    }
    """ % args.pid)
else:
    bpf_text = bpf_text.replace('PID_FILTER', '')

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

b = BPF(text=bpf_text)
if not is_support_kfunc:
    b.attach_kprobe(event="vfs_read",         fn_name="do_read")
    b.attach_kprobe(event="vfs_write",        fn_name="do_write")
    b.attach_kprobe(event="vfs_fsync_range",  fn_name="do_fsync")
    b.attach_kprobe(event="vfs_open",         fn_name="do_open")
    b.attach_kprobe(event="vfs_create",       fn_name="do_create")

# stat column labels and indexes
stat_types = {
    "READ": 1,
    "WRITE": 2,
    "FSYNC": 3,
    "OPEN": 4,
    "CREATE": 5
}

# header
print("%-8s  " % "TIME", end="")
for stype in stat_types.keys():
    print(" %8s" % (stype + "/s"), end="")
    idx = stat_types[stype]
print("")

# output
exiting = 0 if args.interval else 1
while (1):
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = 1

    print("%-8s: " % strftime("%H:%M:%S"), end="")
    # print each statistic as a column
    for stype in stat_types.keys():
        idx = stat_types[stype]
        try:
            val = b["stats"][c_int(idx)].value / int(args.interval)
            print(" %8d" % val, end="")
        except:
            print(" %8d" % 0, end="")
    b["stats"].clear()
    print("")

    countdown -= 1
    if exiting or countdown == 0:
        exit()

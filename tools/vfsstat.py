#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# vfsstat   Count some VFS calls.
#           For Linux, uses BCC, eBPF. See .c file.
#
# Written as a basic example of counting multiple events as a stat tool.
#
# USAGE: vfsstat [interval [count]]
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Aug-2015   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from ctypes import c_int
from time import sleep, strftime
from sys import argv

def usage():
    print("USAGE: %s [interval [count]]" % argv[0])
    exit()

# arguments
interval = 1
count = -1
if len(argv) > 1:
    try:
        interval = int(argv[1])
        if interval == 0:
            raise
        if len(argv) > 2:
            count = int(argv[2])
    except:  # also catches -h, --help
        usage()

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

static void stats_increment(int key) {
    u64 *leaf = stats.lookup(&key);
    if (leaf) (*leaf)++;
}
"""

bpf_text_kprobe = """
void do_read(struct pt_regs *ctx) { stats_increment(S_READ); }
void do_write(struct pt_regs *ctx) { stats_increment(S_WRITE); }
void do_fsync(struct pt_regs *ctx) { stats_increment(S_FSYNC); }
void do_open(struct pt_regs *ctx) { stats_increment(S_OPEN); }
void do_create(struct pt_regs *ctx) { stats_increment(S_CREATE); }
"""

bpf_text_kfunc = """
KFUNC_PROBE(vfs_read, int unused)   { stats_increment(S_READ); }
KFUNC_PROBE(vfs_write, int unused)  { stats_increment(S_WRITE); }
KFUNC_PROBE(vfs_fsync, int unused)  { stats_increment(S_FSYNC); }
KFUNC_PROBE(vfs_open, int unused)   { stats_increment(S_OPEN); }
KFUNC_PROBE(vfs_create, int unused) { stats_increment(S_CREATE); }
"""

is_support_kfunc = BPF.support_kfunc()
#is_support_kfunc = False #BPF.support_kfunc()
if is_support_kfunc:
    bpf_text += bpf_text_kfunc
else:
    bpf_text += bpf_text_kprobe

b = BPF(text=bpf_text)
if not is_support_kfunc:
    b.attach_kprobe(event="vfs_read",   fn_name="do_read")
    b.attach_kprobe(event="vfs_write",  fn_name="do_write")
    b.attach_kprobe(event="vfs_fsync",  fn_name="do_fsync")
    b.attach_kprobe(event="vfs_open",   fn_name="do_open")
    b.attach_kprobe(event="vfs_create", fn_name="do_create")

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
i = 0
while (1):
    if count > 0:
        i += 1
        if i > count:
            exit()
    try:
        sleep(interval)
    except KeyboardInterrupt:
        pass
        exit()

    print("%-8s: " % strftime("%H:%M:%S"), end="")
    # print each statistic as a column
    for stype in stat_types.keys():
        idx = stat_types[stype]
        try:
            val = b["stats"][c_int(idx)].value / interval
            print(" %8d" % val, end="")
        except:
            print(" %8d" % 0, end="")
    b["stats"].clear()
    print("")

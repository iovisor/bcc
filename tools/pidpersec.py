#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# pidpersec Count new processes (via fork).
#           For Linux, uses BCC, eBPF. See .c file.
#
# USAGE: pidpersec
#
# Written as a basic example of counting an event.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 11-Aug-2015   Brendan Gregg   Created this.

from bcc import BPF
from ctypes import c_int
from time import sleep, strftime

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>

enum stat_types {
    S_COUNT = 1,
    S_MAXSTAT
};

BPF_ARRAY(stats, u64, S_MAXSTAT);

static void stats_increment(int key) {
    u64 *leaf = stats.lookup(&key);
    if (leaf) (*leaf)++;
}

void do_count(struct pt_regs *ctx) { stats_increment(S_COUNT); }
""")
b.attach_kprobe(event="sched_fork", fn_name="do_count")

# stat indexes
S_COUNT = c_int(1)

# header
print("Tracing... Ctrl-C to end.")

# output
while (1):
    try:
        sleep(1)
    except KeyboardInterrupt:
        exit()

    print("%s: PIDs/sec: %d" % (strftime("%H:%M:%S"),
        b["stats"][S_COUNT].value))
    b["stats"].clear()

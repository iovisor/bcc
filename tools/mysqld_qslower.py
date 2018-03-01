#!/usr/bin/python
#
# mysqld_qslower    MySQL server queries slower than a threshold.
#                   For Linux, uses BCC, BPF. Embedded C.
#
# USAGE: mysqld_qslower PID [min_ms]
#
# By default, a threshold of 1.0 ms is used. Set this to 0 ms to trace all
# queries (verbose).
#
# This uses USDT probes, and needs a MySQL server with -DENABLE_DTRACE=1.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 30-Jul-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF, USDT
import sys
import ctypes as ct

# arguments
def usage():
    print("USAGE: mysqld_latency PID [min_ms]")
    exit()
if len(sys.argv) < 2:
    usage()
if sys.argv[1][0:1] == "-":
    usage()
pid = int(sys.argv[1])
min_ns = 1 * 1000000
min_ms_text = 1
if len(sys.argv) == 3:
    min_ns = float(sys.argv[2]) * 1000000
    min_ms_text = sys.argv[2]
debug = 0
QUERY_MAX = 128

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

#define QUERY_MAX	""" + str(QUERY_MAX) + """

struct start_t {
    u64 ts;
    char *query;
};

struct data_t {
    u64 pid;
    u64 ts;
    u64 delta;
    char query[QUERY_MAX];
};

BPF_HASH(start_tmp, u32, struct start_t);
BPF_PERF_OUTPUT(events);

int do_start(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    struct start_t start = {};
    start.ts = bpf_ktime_get_ns();
    bpf_usdt_readarg(1, ctx, &start.query);
    start_tmp.update(&pid, &start);
    return 0;
};

int do_done(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    struct start_t *sp;

    sp = start_tmp.lookup(&pid);
    if (sp == 0) {
        // missed tracing start
        return 0;
    }

    // check if query exceeded our threshold
    u64 delta = bpf_ktime_get_ns() - sp->ts;
    if (delta >= """ + str(min_ns) + """) {
        // populate and emit data struct
        struct data_t data = {.pid = pid, .ts = sp->ts, .delta = delta};
        bpf_probe_read(&data.query, sizeof(data.query), (void *)sp->query);
        events.perf_submit(ctx, &data, sizeof(data));
    }

    start_tmp.delete(&pid);

    return 0;
};

"""

# enable USDT probe from given PID
u = USDT(pid=pid)
u.enable_probe(probe="query__start", fn_name="do_start")
u.enable_probe(probe="query__done", fn_name="do_done")
if debug:
    print(u.get_text())
    print(bpf_text)

# initialize BPF
b = BPF(text=bpf_text, usdt_contexts=[u])

# header
print("Tracing MySQL server queries for PID %d slower than %s ms..." % (pid,
    min_ms_text))
print("%-14s %-6s %8s %s" % ("TIME(s)", "PID", "MS", "QUERY"))

class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulonglong),
        ("ts", ct.c_ulonglong),
        ("delta", ct.c_ulonglong),
        ("query", ct.c_char * QUERY_MAX)
    ]

# process event
start = 0
def print_event(cpu, data, size):
    global start
    event = ct.cast(data, ct.POINTER(Data)).contents
    if start == 0:
        start = event.ts
    print("%-14.6f %-6d %8.3f %s" % (float(event.ts - start) / 1000000000,
        event.pid, float(event.delta) / 1000000, event.query))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    b.perf_buffer_poll()

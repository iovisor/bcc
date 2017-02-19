#!/usr/bin/python
#
# dbslower      Trace MySQL and PostgreSQL queries slower than a threshold.
#
# USAGE: dbslower [-v] [-p PID [PID ...]] [-m THRESHOLD] {mysql,postgres}
#
# By default, a threshold of 1ms is used. Set the threshold to 0 to trace all
# queries (verbose). If no PID is provided, the script attempts to discover
# all MySQL or PostgreSQL database processes.
#
# This tool uses USDT probes, which means it needs MySQL and PostgreSQL built
# with USDT (DTrace) support.
#
# Strongly inspired by Brendan Gregg's work on the mysqld_qslower script.
#
# Copyright 2017, Sasha Goldshtein
# Licensed under the Apache License, Version 2.0
#
# 15-Feb-2017   Sasha Goldshtein   Created this.

from bcc import BPF, USDT
import argparse
import ctypes as ct
import subprocess

examples = """examples:
    dbslower postgres            # trace PostgreSQL queries slower than 1ms
    dbslower postgres -p 188 322 # trace specific PostgreSQL processes
    dbslower mysql -p 480 -m 30  # trace MySQL queries slower than 30ms
    dbslower mysql -p 480 -v     # trace MySQL queries & print the BPF program
"""
parser = argparse.ArgumentParser(
    description="",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-v", "--verbose", action="store_true",
    help="print the BPF program")
parser.add_argument("db", choices=["mysql", "postgres"],
    help="the database engine to use")
parser.add_argument("-p", "--pid", type=int, nargs='*',
    dest="pids", metavar="PID", help="the pid(s) to trace")
parser.add_argument("-m", "--threshold", type=int, default=1,
    help="trace queries slower than this threshold (ms)")
args = parser.parse_args()

if not args.pids or len(args.pids) == 0:
    if args.db == "mysql":
        args.pids = map(int, subprocess.check_output(
                                        "pidof mysqld".split()).split())
    elif args.db == "postgres":
        args.pids = map(int, subprocess.check_output(
                                        "pidof postgres".split()).split())

threshold_ns = args.threshold * 1000000

program = """
#include <linux/ptrace.h>

struct temp_t {
    u64 timestamp;
    char *query;
};

struct data_t {
    u64 pid;
    u64 timestamp;
    u64 duration;
    char query[256];
};

BPF_HASH(temp, u64, struct temp_t);
BPF_PERF_OUTPUT(events);

int probe_start(struct pt_regs *ctx) {
    struct temp_t tmp = {};
    tmp.timestamp = bpf_ktime_get_ns();
    bpf_usdt_readarg(1, ctx, &tmp.query);
    u64 pid = bpf_get_current_pid_tgid();
    temp.update(&pid, &tmp);
    return 0;
}

int probe_end(struct pt_regs *ctx) {
    struct temp_t *tempp;
    u64 pid = bpf_get_current_pid_tgid();
    tempp = temp.lookup(&pid);
    if (!tempp)
        return 0;

    u64 delta = bpf_ktime_get_ns() - tempp->timestamp;
    if (delta >= """ + str(threshold_ns) + """) {
        struct data_t data = {};
        data.pid = pid >> 32;   // only process id
        data.timestamp = tempp->timestamp;
        data.duration = delta;
        bpf_probe_read(&data.query, sizeof(data.query), tempp->query);
        events.perf_submit(ctx, &data, sizeof(data));
    }
    temp.delete(&pid);
    return 0;
}
"""

usdts = map(lambda pid: USDT(pid=pid), args.pids)
for usdt in usdts:
    usdt.enable_probe("query__start", "probe_start")
    usdt.enable_probe("query__done", "probe_end")

bpf = BPF(text=program, usdt_contexts=usdts)
if args.verbose:
    print('\n'.join(map(lambda u: u.get_text(), usdts)))
    print(program)

class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulonglong),
        ("timestamp", ct.c_ulonglong),
        ("delta", ct.c_ulonglong),
        ("query", ct.c_char * 256)
    ]

start = BPF.monotonic_time()

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print("%-14.6f %-6d %8.3f %s" % (
        float(event.timestamp - start) / 1000000000,
        event.pid, float(event.delta) / 1000000, event.query))

print("Tracing database queries for pids %s slower than %d ms..." %
      (', '.join(map(str, args.pids)), args.threshold))
print("%-14s %-6s %8s %s" % ("TIME(s)", "PID", "MS", "QUERY"))

bpf["events"].open_perf_buffer(print_event, page_cnt=64)
while True:
    bpf.kprobe_poll()

#!/usr/bin/python
#
# dbslower      Trace MySQL and PostgreSQL queries slower than a threshold.
#
# USAGE: dbslower [-v] [-p PID [PID ...]] [-b PATH_TO_BINARY] [-m THRESHOLD] {mysql,postgres}
#
# By default, a threshold of 1ms is used. Set the threshold to 0 to trace all
# queries (verbose). 
# 
# Script works in two different modes: 
# 1) USDT probes, which means it needs MySQL and PostgreSQL built with 
# USDT (DTrace) support.
# 2) uprobe and uretprobe on exported function of binary specified by 
# PATH_TO_BINARY parameter. (At the moment only MySQL support)
# 
# If no PID or PATH_TO_BINARY is provided, the script attempts to discover
# all MySQL or PostgreSQL database processes and uses USDT probes.
#
# Strongly inspired by Brendan Gregg's work on the mysqld_qslower script.
#
# Copyright 2017, Sasha Goldshtein
# Licensed under the Apache License, Version 2.0
#
# 15-Feb-2017   Sasha Goldshtein   Created this.

from bcc import BPF, USDT
import argparse
import re
import ctypes as ct
import subprocess

examples = """examples:
    dbslower postgres            # trace PostgreSQL queries slower than 1ms
    dbslower postgres -p 188 322 # trace specific PostgreSQL processes
    dbslower mysql -p 480 -m 30  # trace MySQL queries slower than 30ms
    dbslower mysql -p 480 -v     # trace MySQL queries & print the BPF program
    dbslower mysql -b $(which mysqld)  # trace MySQL queries with uprobes
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
parser.add_argument("-b", "--binary", type=str,
    dest="path", metavar="PATH", help="path to binary")
parser.add_argument("-m", "--threshold", type=int, default=1,
    help="trace queries slower than this threshold (ms)")
args = parser.parse_args()

threshold_ns = args.threshold * 1000000

program_uprobe = """
#include <uapi/linux/ptrace.h>

struct temp_t {
    u64 timestamp;
    char query[256];
};

struct data_t {
    u64 pid;
    u64 timestamp;
    u64 duration;
    char query[256];
};

BPF_HASH(temp, u64, struct temp_t);
BPF_PERF_OUTPUT(events);

int mysql56_dispatch_start(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 command  = (u64) PT_REGS_PARM1(ctx);

    if (command == 3) {
        struct temp_t tmp = {};
        tmp.timestamp = bpf_ktime_get_ns();
        bpf_probe_read(&tmp.query, sizeof(tmp.query), (void*) PT_REGS_PARM3(ctx));

        temp.update(&pid, &tmp);
    }
    return 0;
};

int mysql56_dispatch_end(struct pt_regs *ctx) {
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
};

int mysql57_dispatch_start(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 command  = (u64) PT_REGS_PARM3(ctx);

    if (command == 3) {
        struct temp_t tmp = {};
        tmp.timestamp = bpf_ktime_get_ns();

        void* st = (void*) PT_REGS_PARM2(ctx);
        char* query;
        bpf_probe_read(&query, sizeof(query), st);
        bpf_probe_read(&tmp.query, sizeof(tmp.query), query);

        temp.update(&pid, &tmp);
    }
    return 0;
};

int mysql57_dispatch_end(struct pt_regs *ctx) {
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
};
"""

program_udst = """
#include <uapi/linux/ptrace.h>

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

if args.path and not args.pids:
    # Uprobes mode
    program = program_uprobe

    symbols = subprocess.check_output(["nm", "-aD", args.path])
    bpf = BPF(text=program)
    if args.db == "mysql":
        dispatch_fname = [name for name in symbols.split('\n') if name.find("dispatch_command") >= 0]

        if len(dispatch_fname) == 0:
            print("Cant find function 'dispatch_command' in %s" % (args.path))
            exit(1)

        m = re.search("\\w+dispatch_command\\w+", dispatch_fname[0])
        if m:
            func_name = m.group(0)
        else:
            print("Cant extract real 'dispatch_command' function name from %s" % (dispatch_fname[0]))
            exit(1)

        if func_name.find("COM_DATA") >= 0:
            bpf.attach_uprobe(name=args.path, sym=func_name, fn_name="mysql57_dispatch_start")
            bpf.attach_uretprobe(name=args.path, sym=func_name, fn_name="mysql57_dispatch_end")
        else:
            bpf.attach_uprobe(name=args.path, sym=func_name, fn_name="mysql56_dispatch_start")
            bpf.attach_uretprobe(name=args.path, sym=func_name, fn_name="mysql56_dispatch_end")
    else:
        # Placeholder for PostrgeSQL
        # Look on functions initStringInfo, pgstat_report_activity, EndCommand, NullCommand
        print("Sorry at the moment PostgreSQL supports only USDT")
        exit(1)
else:
    # USDT mode
    program = program_udst

    if not args.pids or len(args.pids) == 0:
        if args.db == "mysql":
            args.pids = map(int, subprocess.check_output(
                                            "pidof mysqld".split()).split())
        elif args.db == "postgres":
            args.pids = map(int, subprocess.check_output(
                                            "pidof postgres".split()).split())

    usdts = map(lambda pid: USDT(pid=pid), args.pids)
    for usdt in usdts:
        usdt.enable_probe("query__start", "probe_start")
        usdt.enable_probe("query__done", "probe_end")
    if args.verbose:
        print('\n'.join(map(lambda u: u.get_text(), usdts)))

    bpf = BPF(text=program, usdt_contexts=usdts)

if args.verbose:
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

# print("Tracing database queries for pids %s slower than %d ms..." %
#       (', '.join(map(str, args.pids)), args.threshold))
print("%-14s %-6s %8s %s" % ("TIME(s)", "PID", "MS", "QUERY"))

bpf["events"].open_perf_buffer(print_event, page_cnt=64)
while True:
    bpf.kprobe_poll()

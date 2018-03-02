#!/usr/bin/python
#
# dbslower      Trace MySQL and PostgreSQL queries slower than a threshold.
#
# USAGE: dbslower [-v] [-p PID [PID ...]] [-b PATH_TO_BINARY] [-m THRESHOLD]
#                 {mysql,postgres}
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
    dbslower mysql -x $(which mysqld)  # trace MySQL queries with uprobes
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
parser.add_argument("-x", "--exe", type=str,
    dest="path", metavar="PATH", help="path to binary")
parser.add_argument("-m", "--threshold", type=int, default=1,
    help="trace queries slower than this threshold (ms)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

threshold_ns = args.threshold * 1000000

mode = "USDT"
if args.path and not args.pids:
    if args.db == "mysql":
        regex = "\\w+dispatch_command\\w+"
        symbols = BPF.get_user_functions_and_addresses(args.path, regex)

        if len(symbols) == 0:
            print("Can't find function 'dispatch_command' in %s" % (args.path))
            exit(1)

        (mysql_func_name, addr) = symbols[0]

        if mysql_func_name.find("COM_DATA") >= 0:
            mode = "MYSQL57"
        else:
            mode = "MYSQL56"
    else:
        # Placeholder for PostrgeSQL
        # Look on functions initStringInfo, pgstat_report_activity, EndCommand,
        # NullCommand
        print("Sorry at the moment PostgreSQL supports only USDT")
        exit(1)

program = """
#include <uapi/linux/ptrace.h>

DEFINE_THRESHOLD
DEFINE_USDT
DEFINE_MYSQL56
DEFINE_MYSQL57

struct temp_t {
    u64 timestamp;
#ifdef USDT
    char *query;
#else
    /*
    MySQL clears query packet before uretprobe call - so copy query in advance
    */
    char query[256];
#endif //USDT
};

struct data_t {
    u64 pid;
    u64 timestamp;
    u64 duration;
    char query[256];
};

BPF_HASH(temp, u64, struct temp_t);
BPF_PERF_OUTPUT(events);

int query_start(struct pt_regs *ctx) {

#if defined(MYSQL56) || defined(MYSQL57)
/*
Trace only packets with enum_server_command == COM_QUERY
*/
    #ifdef MYSQL56
    u64 command  = (u64) PT_REGS_PARM1(ctx);
    #else //MYSQL57
    u64 command  = (u64) PT_REGS_PARM3(ctx);
    #endif
    if (command != 3) return 0;
#endif

    struct temp_t tmp = {};
    tmp.timestamp = bpf_ktime_get_ns();

#if defined(MYSQL56)
    bpf_probe_read(&tmp.query, sizeof(tmp.query), (void*) PT_REGS_PARM3(ctx));
#elif defined(MYSQL57)
    void* st = (void*) PT_REGS_PARM2(ctx);
    char* query;
    bpf_probe_read(&query, sizeof(query), st);
    bpf_probe_read(&tmp.query, sizeof(tmp.query), query);
#else //USDT
    bpf_usdt_readarg(1, ctx, &tmp.query);
#endif

    u64 pid = bpf_get_current_pid_tgid();
    temp.update(&pid, &tmp);
    return 0;
}

int query_end(struct pt_regs *ctx) {
    struct temp_t *tempp;
    u64 pid = bpf_get_current_pid_tgid();
    tempp = temp.lookup(&pid);
    if (!tempp)
        return 0;

    u64 delta = bpf_ktime_get_ns() - tempp->timestamp;
#ifdef THRESHOLD
    if (delta >= THRESHOLD) {
#endif //THRESHOLD
        struct data_t data = {};
        data.pid = pid >> 32;   // only process id
        data.timestamp = tempp->timestamp;
        data.duration = delta;
        bpf_probe_read(&data.query, sizeof(data.query), tempp->query);
        events.perf_submit(ctx, &data, sizeof(data));
#ifdef THRESHOLD
    }
#endif //THRESHOLD
    temp.delete(&pid);
    return 0;
};
""".replace("DEFINE_USDT", "#define USDT" if mode == "USDT" else "") \
   .replace("DEFINE_MYSQL56", "#define MYSQL56" if mode == "MYSQL56" else "") \
   .replace("DEFINE_MYSQL57", "#define MYSQL57" if mode == "MYSQL57" else "") \
   .replace("DEFINE_THRESHOLD",
            "#define THRESHOLD %d" % threshold_ns if threshold_ns > 0 else "")

if mode.startswith("MYSQL"):
    # Uprobes mode
    bpf = BPF(text=program)
    bpf.attach_uprobe(name=args.path, sym=mysql_func_name,
                      fn_name="query_start")
    bpf.attach_uretprobe(name=args.path, sym=mysql_func_name,
                         fn_name="query_end")
else:
    # USDT mode
    if not args.pids or len(args.pids) == 0:
        if args.db == "mysql":
            args.pids = map(int, subprocess.check_output(
                                            "pidof mysqld".split()).split())
        elif args.db == "postgres":
            args.pids = map(int, subprocess.check_output(
                                            "pidof postgres".split()).split())

    usdts = map(lambda pid: USDT(pid=pid), args.pids)
    for usdt in usdts:
        usdt.enable_probe("query__start", "query_start")
        usdt.enable_probe("query__done", "query_end")
    if args.verbose:
        print('\n'.join(map(lambda u: u.get_text(), usdts)))

    bpf = BPF(text=program, usdt_contexts=usdts)

if args.verbose or args.ebpf:
    print(program)
    if args.ebpf:
        exit()

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

if mode.startswith("MYSQL"):
    print("Tracing database queries for application %s slower than %d ms..." %
        (args.path, args.threshold))
else:
    print("Tracing database queries for pids %s slower than %d ms..." %
        (', '.join(map(str, args.pids)), args.threshold))

print("%-14s %-6s %8s %s" % ("TIME(s)", "PID", "MS", "QUERY"))

bpf["events"].open_perf_buffer(print_event, page_cnt=64)
while True:
    bpf.perf_buffer_poll()

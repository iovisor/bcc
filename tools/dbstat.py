#!/usr/bin/python
#
# dbstat        Display a histogram of MySQL and PostgreSQL query latencies.
#
# USAGE: dbstat [-v] [-p PID [PID ...]] [-m THRESHOLD] [-u]
#               [-i INTERVAL] {mysql,postgres}
#
# This tool uses USDT probes, which means it needs MySQL and PostgreSQL built
# with USDT (DTrace) support.
#
# Copyright 2017, Sasha Goldshtein
# Licensed under the Apache License, Version 2.0
#
# 15-Feb-2017   Sasha Goldshtein   Created this.

from bcc import BPF, USDT
import argparse
import subprocess
from time import sleep, strftime

examples = """
    dbstat postgres     # display a histogram of PostgreSQL query latencies
    dbstat mysql -v     # display MySQL latencies and print the BPF program
    dbstat mysql -u     # display query latencies in microseconds (default: ms)
    dbstat mysql -m 5   # trace only queries slower than 5ms
    dbstat mysql -p 408 # trace queries in a specific process
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
parser.add_argument("-m", "--threshold", type=int, default=0,
    help="trace queries slower than this threshold (ms)")
parser.add_argument("-u", "--microseconds", action="store_true",
    help="display query latencies in microseconds (default: milliseconds)")
parser.add_argument("-i", "--interval", type=int, default=99999999999,
    help="print summary at this interval (seconds)")
args = parser.parse_args()

if not args.pids or len(args.pids) == 0:
    if args.db == "mysql":
        args.pids = map(int, subprocess.check_output(
                                        "pidof mysqld".split()).split())
    elif args.db == "postgres":
        args.pids = map(int, subprocess.check_output(
                                        "pidof postgres".split()).split())

program = """
#include <uapi/linux/ptrace.h>

BPF_HASH(temp, u64, u64);
BPF_HISTOGRAM(latency);

int probe_start(struct pt_regs *ctx) {
    u64 timestamp = bpf_ktime_get_ns();
    u64 pid = bpf_get_current_pid_tgid();
    temp.update(&pid, &timestamp);
    return 0;
}

int probe_end(struct pt_regs *ctx) {
    u64 *timestampp;
    u64 pid = bpf_get_current_pid_tgid();
    timestampp = temp.lookup(&pid);
    if (!timestampp)
        return 0;

    u64 delta = bpf_ktime_get_ns() - *timestampp;
    FILTER
    delta /= SCALE;
    latency.increment(bpf_log2l(delta));
    temp.delete(&pid);
    return 0;
}
"""
program = program.replace("SCALE", str(1000 if args.microseconds else 1000000))
program = program.replace("FILTER", "" if args.threshold == 0 else
        "if (delta / 1000000 < %d) { return 0; }" % args.threshold)

usdts = map(lambda pid: USDT(pid=pid), args.pids)
for usdt in usdts:
    usdt.enable_probe("query__start", "probe_start")
    usdt.enable_probe("query__done", "probe_end")

if args.verbose:
    print('\n'.join(map(lambda u: u.get_text(), usdts)))
    print(program)

bpf = BPF(text=program, usdt_contexts=usdts)

print("Tracing database queries for pids %s slower than %d ms..." %
      (', '.join(map(str, args.pids)), args.threshold))

latencies = bpf["latency"]

def print_hist():
    print("[%s]" % strftime("%H:%M:%S"))
    latencies.print_log2_hist("query latency (%s)" %
                              ("us" if args.microseconds else "ms"))
    print("")
    latencies.clear()

while True:
    try:
        sleep(args.interval)
        print_hist()
    except KeyboardInterrupt:
        print_hist()
        break

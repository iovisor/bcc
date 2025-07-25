#!/usr/bin/env python
#
# syscount   Summarize syscall counts and latencies.
#
# USAGE: syscount [-h] [-p PID] [-t TID] [-i INTERVAL] [-d DURATION] [-T TOP]
#                 [-x] [-e ERRNO] [-L] [-m] [-P] [-l] [--syscall SYSCALL]
#
# Copyright 2017, Sasha Goldshtein.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 15-Feb-2017   Sasha Goldshtein    Created this.
# 16-May-2022   Rocky Xing          Added TID filter support.
# 26-Jul-2022   Rocky Xing          Added syscall filter support.
# 12-Jul-2025   Rocky Xing          Execute a program and trace it's syscalls.

from time import sleep, strftime
import argparse
import errno
import itertools
import os
import sys
import signal
from bcc import BPF
from bcc.exec import run_cmd, cmd_ready, cmd_exited
from bcc.utils import printb
from bcc.syscall import syscall_name, syscalls

if sys.version_info.major < 3:
    izip_longest = itertools.izip_longest
else:
    izip_longest = itertools.zip_longest

# signal handler
def signal_ignore(signal, frame):
    print()

def handle_errno(errstr):
    try:
        return abs(int(errstr))
    except ValueError:
        pass

    try:
        return getattr(errno, errstr)
    except AttributeError:
        raise argparse.ArgumentTypeError("couldn't map %s to an errno" % errstr)


parser = argparse.ArgumentParser(
    description="Summarize syscall counts and latencies.")
parser.add_argument("-p", "--pid", type=int,
    help="trace only this pid")
parser.add_argument("-t", "--tid", type=int,
    help="trace only this tid")
parser.add_argument("-c", "--ppid", type=int,
    help="trace only child of this pid")
parser.add_argument("-i", "--interval", type=int,
    help="print summary at this interval (seconds)")
parser.add_argument("-d", "--duration", type=int,
    help="total duration of trace, in seconds")
parser.add_argument("-T", "--top", type=int, default=10,
    help="print only the top syscalls by count or latency")
parser.add_argument("-x", "--failures", action="store_true",
    help="trace only failed syscalls (return < 0)")
parser.add_argument("-e", "--errno", type=handle_errno,
    help="trace only syscalls that return this error (numeric or EPERM, etc.)")
parser.add_argument("-L", "--latency", action="store_true",
    help="collect syscall latency")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="display latency in milliseconds (default: microseconds)")
parser.add_argument("-P", "--process", action="store_true",
    help="count by process and not by syscall")
parser.add_argument("-l", "--list", action="store_true",
    help="print list of recognized syscalls and exit")
parser.add_argument("--syscall", type=str,
    help="trace this syscall only (use option -l to get all recognized syscalls)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
parser.add_argument('--exec', nargs=argparse.REMAINDER,
    help="execute command (as the last parameter, "
        "supports multiple parameters, for example: --exec ls -l /tmp")
args = parser.parse_args()
if args.duration and not args.interval:
    args.interval = args.duration
if not args.interval:
    args.interval = 99999999

if args.pid and args.exec:
    print("ERROR: can only use -p or --exec. Exiting.")
    exit()

if args.exec is not None and len(args.exec) == 0:
    print("ERROR: --exec without command. Exiting.")
    exit()

syscall_nr = -1
if args.syscall is not None:
    syscall = bytes(args.syscall, 'utf-8')
    for key, value in syscalls.items():
        if syscall == value:
            syscall_nr = key
            break
    if syscall_nr == -1:
        print("Error: syscall '%s' not found. Exiting." % args.syscall)
        sys.exit(1)

if args.list:
    for grp in izip_longest(*(iter(sorted(syscalls.values())),) * 4):
        print("   ".join(["%-22s" % s.decode() for s in grp if s is not None]))
    sys.exit(0)

text = """
#include <linux/sched.h>

#ifdef LATENCY
struct data_t {
    u64 count;
    u64 total_ns;
};

BPF_HASH(start, u64, u64);
BPF_HASH(data, u32, struct data_t);
#else
BPF_HASH(data, u32, u64);
#endif

#ifdef LATENCY
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

#ifdef FILTER_SYSCALL_NR
    if (args->id != FILTER_SYSCALL_NR)
        return 0;
#endif

#ifdef FILTER_PID
    if (pid != FILTER_PID)
        return 0;
#endif

#ifdef FILTER_TID
    if (tid != FILTER_TID)
        return 0;
#endif

#ifdef FILTER_PPID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = task->real_parent->tgid;
    if (ppid != FILTER_PPID)
        return 0;
#endif

    u64 t = bpf_ktime_get_ns();
    start.update(&pid_tgid, &t);
    return 0;
}
#endif

TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

#ifdef FILTER_SYSCALL_NR
    if (args->id != FILTER_SYSCALL_NR)
        return 0;
#endif

#ifdef FILTER_PID
    if (pid != FILTER_PID)
        return 0;
#endif

#ifdef FILTER_TID
    if (tid != FILTER_TID)
        return 0;
#endif

#ifdef FILTER_PPID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = task->real_parent->tgid;
    if (ppid != FILTER_PPID)
        return 0;
#endif

#ifdef FILTER_FAILED
    if (args->ret >= 0)
        return 0;
#endif

#ifdef FILTER_ERRNO
    if (args->ret != -FILTER_ERRNO)
        return 0;
#endif

#ifdef BY_PROCESS
    u32 key = pid_tgid >> 32;
#else
    u32 key = args->id;
#endif

#ifdef LATENCY
    struct data_t *val, zero = {};
    u64 *start_ns = start.lookup(&pid_tgid);
    if (!start_ns)
        return 0;

    val = data.lookup_or_try_init(&key, &zero);
    if (val) {
        lock_xadd(&val->count, 1);
        lock_xadd(&val->total_ns, bpf_ktime_get_ns() - *start_ns);
    }
#else
    u64 *val, zero = 0;
    val = data.lookup_or_try_init(&key, &zero);
    if (val) {
        lock_xadd(val, 1);
    }
#endif
    return 0;
}
"""

if args.pid:
    text = ("#define FILTER_PID %d\n" % args.pid) + text
elif args.exec:
    text = ("#define FILTER_PID %d\n" % run_cmd(args.exec)) + text
elif args.tid:
    text = ("#define FILTER_TID %d\n" % args.tid) + text
elif args.ppid:
    text = ("#define FILTER_PPID %d\n" % args.ppid) + text
if args.failures:
    text = "#define FILTER_FAILED\n" + text
if args.errno:
    text = "#define FILTER_ERRNO %d\n" % abs(args.errno) + text
if args.latency:
    text = "#define LATENCY\n" + text
if args.process:
    text = "#define BY_PROCESS\n" + text
if args.syscall is not None:
    text = ("#define FILTER_SYSCALL_NR %d\n" % syscall_nr) + text
if args.ebpf:
    print(text)
    exit()

bpf = BPF(text=text)

if args.exec:
   cmd_ready()

def print_stats():
    if args.latency:
        print_latency_stats()
    else:
        print_count_stats()

agg_colname = "PID    COMM" if args.process else "SYSCALL"
time_colname = "TIME (ms)" if args.milliseconds else "TIME (us)"

def comm_for_pid(pid):
    try:
        return open("/proc/%d/comm" % pid, "rb").read().strip()
    except Exception:
        return b"[unknown]"

def agg_colval(key):
    if args.process:
        return b"%-6d %-15s" % (key.value, comm_for_pid(key.value))
    else:
        return syscall_name(key.value)

# check whether hash table batch ops is supported
htab_batch_ops = True if BPF.kernel_struct_has_field(b'bpf_map_ops',
        b'map_lookup_and_delete_batch') == 1 else False

def print_count_stats():
    data = bpf["data"]
    print("[%s]" % strftime("%H:%M:%S"))
    print("%-22s %8s" % (agg_colname, "COUNT"))
    for k, v in sorted(data.items_lookup_and_delete_batch()
                       if htab_batch_ops else data.items(),
                       key=lambda kv: -kv[1].value)[:args.top]:
        if k.value == 0xFFFFFFFF:
            continue    # happens occasionally, we don't need it
        printb(b"%-22s %8d" % (agg_colval(k), v.value))
    print("")
    if not htab_batch_ops:
        data.clear()

def print_latency_stats():
    data = bpf["data"]
    print("[%s]" % strftime("%H:%M:%S"))
    print("%-22s %8s %16s" % (agg_colname, "COUNT", time_colname))
    for k, v in sorted(data.items_lookup_and_delete_batch()
                       if htab_batch_ops else data.items(),
                       key=lambda kv: -kv[1].total_ns)[:args.top]:
        if k.value == 0xFFFFFFFF:
            continue    # happens occasionally, we don't need it
        printb((b"%-22s %8d " + (b"%16.6f" if args.milliseconds else b"%16.3f")) %
               (agg_colval(k), v.count,
                v.total_ns / (1e6 if args.milliseconds else 1e3)))
    print("")
    if not htab_batch_ops:
        data.clear()

if args.syscall is not None:
    print("Tracing %ssyscall '%s'... Ctrl+C to quit." %
        ("failed " if args.failures else "", args.syscall))
else:
    print("Tracing %ssyscalls, printing top %d... Ctrl+C to quit." %
        ("failed " if args.failures else "", args.top))
exiting = 0 if args.interval else 1
seconds = 0
while True:
    try:
        sleep(args.interval)
        seconds += args.interval
    except KeyboardInterrupt:
        exiting = 1
        signal.signal(signal.SIGINT, signal_ignore)
    if args.duration and seconds >= args.duration:
        exiting = 1
    if args.exec and cmd_exited():
        exiting = 1

    print_stats()

    if exiting:
        print("Detaching...")
        exit()

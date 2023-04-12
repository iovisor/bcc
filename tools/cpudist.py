#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# cpudist   Summarize on- and off-CPU time per task as a histogram.
#
# USAGE: cpudist [-h] [-O] [-T] [-m] [-P] [-L] [-p PID] [-I] [-e] [interval] [count]
#
# This measures the time a task spends on or off the CPU, and shows this time
# as a histogram, optionally per-process.
#
# By default CPU idle time are excluded by simply excluding PID 0.
#
# Copyright 2016 Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 27-Mar-2022   Rocky Xing      Changed to exclude CPU idle time by default.
# 25-Jul-2022   Rocky Xing      Added extension summary support.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse

examples = """examples:
    cpudist              # summarize on-CPU time as a histogram
    cpudist -O           # summarize off-CPU time as a histogram
    cpudist 1 10         # print 1 second summaries, 10 times
    cpudist -mT 1        # 1s summaries, milliseconds, and timestamps
    cpudist -P           # show each PID separately
    cpudist -p 185       # trace PID 185 only
    cpudist -I           # include CPU idle time
    cpudist -e           # show extension summary (average/total/count)
"""
parser = argparse.ArgumentParser(
    description="Summarize on- and off-CPU time per task as a histogram.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-O", "--offcpu", action="store_true",
    help="measure off-CPU time")
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="millisecond histogram")
parser.add_argument("-P", "--pids", action="store_true",
    help="print a histogram per process ID")
parser.add_argument("-L", "--tids", action="store_true",
    help="print a histogram per thread ID")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-I", "--include-idle", action="store_true",
    help="include CPU idle time")
parser.add_argument("-e", "--extension", action="store_true",
    help="show extension summary (average/total/count)")
parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
countdown = int(args.count)
debug = 0

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
"""

if not args.offcpu:
    bpf_text += "#define ONCPU\n"

bpf_text += """
typedef struct entry_key {
    u32 pid;
    u32 cpu;
} entry_key_t;

typedef struct pid_key {
    u64 id;
    u64 slot;
} pid_key_t;

typedef struct ext_val {
    u64 total;
    u64 count;
} ext_val_t;

BPF_HASH(start, entry_key_t, u64, MAX_PID);
STORAGE

static inline void store_start(u32 tgid, u32 pid, u32 cpu, u64 ts)
{
    if (PID_FILTER)
        return;

    if (IDLE_FILTER)
        return;

    entry_key_t entry_key = { .pid = pid, .cpu = (pid == 0 ? cpu : 0xFFFFFFFF) };
    start.update(&entry_key, &ts);
}

static inline void update_hist(u32 tgid, u32 pid, u32 cpu, u64 ts)
{
    if (PID_FILTER)
        return;

    if (IDLE_FILTER)
        return;

    entry_key_t entry_key = { .pid = pid, .cpu = (pid == 0 ? cpu : 0xFFFFFFFF) };
    u64 *tsp = start.lookup(&entry_key);
    if (tsp == 0)
        return;

    if (ts < *tsp) {
        // Probably a clock issue where the recorded on-CPU event had a
        // timestamp later than the recorded off-CPU event, or vice versa.
        return;
    }
    u64 delta = ts - *tsp;
    FACTOR
    STORE
}

int sched_switch(struct pt_regs *ctx, struct task_struct *prev)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32, pid = pid_tgid;
    u32 cpu = bpf_get_smp_processor_id();

    u32 prev_pid = prev->pid;
    u32 prev_tgid = prev->tgid;
#ifdef ONCPU
    update_hist(prev_tgid, prev_pid, cpu, ts);
#else
    store_start(prev_tgid, prev_pid, cpu, ts);
#endif

BAIL:
#ifdef ONCPU
    store_start(tgid, pid, cpu, ts);
#else
    update_hist(tgid, pid, cpu, ts);
#endif

    return 0;
}
"""

if args.pid:
    bpf_text = bpf_text.replace('PID_FILTER', 'tgid != %s' % args.pid)
else:
    bpf_text = bpf_text.replace('PID_FILTER', '0')

# set idle filter
idle_filter = 'pid == 0'
if args.include_idle:
    idle_filter = '0'
bpf_text = bpf_text.replace('IDLE_FILTER', idle_filter)

if args.milliseconds:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000000;')
    label = "msecs"
else:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000;')
    label = "usecs"

storage_str = ""
store_str = ""

if args.pids or args.tids:
    section = "pid"
    pid = "tgid"
    if args.tids:
        pid = "pid"
        section = "tid"
    storage_str += "BPF_HISTOGRAM(dist, pid_key_t, MAX_PID);"
    store_str += """
    pid_key_t key = {.id = """ + pid + """, .slot = bpf_log2l(delta)};
    dist.increment(key);
    """
else:
    section = ""
    storage_str += "BPF_HISTOGRAM(dist);"
    store_str += "dist.atomic_increment(bpf_log2l(delta));"

if args.extension:
    storage_str += "BPF_ARRAY(extension, ext_val_t, 1);"
    store_str += """
    u32 index = 0;
    ext_val_t *ext_val = extension.lookup(&index);
    if (ext_val) {
        lock_xadd(&ext_val->total, delta);
        lock_xadd(&ext_val->count, 1);
    }
    """

bpf_text = bpf_text.replace("STORAGE", storage_str)
bpf_text = bpf_text.replace("STORE", store_str)

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

max_pid = int(open("/proc/sys/kernel/pid_max").read())

b = BPF(text=bpf_text, cflags=["-DMAX_PID=%d" % max_pid])
b.attach_kprobe(event_re="^finish_task_switch$|^finish_task_switch\.isra\.\d$",
                fn_name="sched_switch")

print("Tracing %s-CPU time... Hit Ctrl-C to end." %
      ("off" if args.offcpu else "on"))

exiting = 0 if args.interval else 1
dist = b.get_table("dist")
if args.extension:
    extension = b.get_table("extension")
while (1):
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = 1

    print()
    if args.timestamp:
        print("%-8s\n" % strftime("%H:%M:%S"), end="")

    def pid_to_comm(pid):
        try:
            comm = open("/proc/%d/comm" % pid, "r").read()
            return "%d %s" % (pid, comm)
        except IOError:
            return str(pid)

    dist.print_log2_hist(label, section, section_print_fn=pid_to_comm)

    if args.extension:
        total = extension[0].total
        count = extension[0].count
        if count > 0:
            print("\navg = %ld %s, total: %ld %s, count: %ld\n" %
                (total / count, label, total, label, count))
        extension.clear()

    dist.clear()

    countdown -= 1
    if exiting or countdown == 0:
        exit()

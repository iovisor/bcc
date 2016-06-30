#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# cpudist   Summarize on- and off-CPU time per task as a histogram.
#
# USAGE: cpudist [-h] [-O] [-T] [-m] [-P] [-L] [-p PID] [interval] [count]
#
# This measures the time a task spends on or off the CPU, and shows this time
# as a histogram, optionally per-process.
#
# Copyright 2016 Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF, Tracepoint
from time import sleep, strftime
import argparse

examples = """examples:
    cpudist              # summarize on-CPU time as a histogram
    cpudist -O           # summarize off-CPU time as a histogram
    cpudist 1 10         # print 1 second summaries, 10 times
    cpudist -mT 1        # 1s summaries, milliseconds, and timestamps
    cpudist -P           # show each PID separately
    cpudist -p 185       # trace PID 185 only
"""
parser = argparse.ArgumentParser(
    description="Summarize on-CPU time per task as a histogram.",
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
parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
args = parser.parse_args()
countdown = int(args.count)
debug = 0

tp = Tracepoint.enable_tracepoint("sched", "sched_switch")
bpf_text = "#include <uapi/linux/ptrace.h>\n"
bpf_text += "#include <linux/sched.h>\n"
bpf_text += tp.generate_decl()
bpf_text += tp.generate_entry_probe()
bpf_text += tp.generate_struct()

if not args.offcpu:
    bpf_text += "#define ONCPU\n"

bpf_text += """
typedef struct pid_key {
    u64 id;
    u64 slot;
} pid_key_t;


BPF_HASH(start, u32, u64);
BPF_HASH(tgid_for_pid, u32, u32);
STORAGE

static inline u32 get_tgid(u32 pid)
{
    u32 *stored_tgid = tgid_for_pid.lookup(&pid);
    if (stored_tgid != 0)
        return *stored_tgid;
    return 0xffffffff;
}

static inline void store_start(u32 tgid, u32 pid, u64 ts)
{
    if (FILTER)
        return;

    start.update(&pid, &ts);
}

static inline void update_hist(u32 tgid, u32 pid, u64 ts)
{
    if (FILTER)
        return;

    u64 *tsp = start.lookup(&pid);
    if (tsp == 0)
        return;

    u64 delta = ts - *tsp;
    FACTOR
    STORE
}

int sched_switch(struct pt_regs *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32, pid = pid_tgid;
    // Keep a mapping of tgid for pid because when sched_switch hits,
    // we only have the tgid information for the *current* pid, but not
    // for the previous one.
    tgid_for_pid.update(&pid, &tgid);

    u64 *di = __trace_di.lookup(&pid_tgid);
    if (di == 0)
        return 0;

    struct sched_switch_trace_entry args = {};
    bpf_probe_read(&args, sizeof(args), (void *)*di);

#ifdef ONCPU
    if (args.prev_state == TASK_RUNNING) {
#else
    if (1) {
#endif
        u32 prev_pid = args.prev_pid;
        u32 prev_tgid = get_tgid(prev_pid);
        if (prev_tgid == 0xffffffff)
            goto BAIL;
#ifdef ONCPU
        update_hist(prev_tgid, prev_pid, ts);
#else
        store_start(prev_tgid, prev_pid, ts);
#endif
    }

BAIL:
#ifdef ONCPU
    store_start(tgid, pid, ts);
#else
    update_hist(tgid, pid, ts);
#endif

    return 0;
}
"""

if args.pid:
    bpf_text = bpf_text.replace('FILTER', 'tgid != %s' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '0')
if args.milliseconds:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000000;')
    label = "msecs"
else:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000;')
    label = "usecs"
if args.pids or args.tids:
    section = "pid"
    pid = "tgid"
    if args.tids:
        pid = "pid"
        section = "tid"
    bpf_text = bpf_text.replace('STORAGE',
        'BPF_HISTOGRAM(dist, pid_key_t);')
    bpf_text = bpf_text.replace('STORE',
        'pid_key_t key = {.id = ' + pid + ', .slot = bpf_log2l(delta)}; ' +
        'dist.increment(key);')
else:
    section = ""
    bpf_text = bpf_text.replace('STORAGE', 'BPF_HISTOGRAM(dist);')
    bpf_text = bpf_text.replace('STORE',
        'dist.increment(bpf_log2l(delta));')
if debug:
    print(bpf_text)

b = BPF(text=bpf_text)
Tracepoint.attach(b)
b.attach_kprobe(event="perf_trace_sched_switch", fn_name="sched_switch")

print("Tracing %s-CPU time... Hit Ctrl-C to end." %
      ("off" if args.offcpu else "on"))

exiting = 0 if args.interval else 1
dist = b.get_table("dist")
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
    dist.clear()

    countdown -= 1
    if exiting or countdown == 0:
        exit()


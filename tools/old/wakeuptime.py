#!/usr/bin/python
#
# wakeuptime    Summarize sleep to wakeup time by waker kernel stack
#               For Linux, uses BCC, eBPF.
#
# USAGE: wakeuptime [-h] [-u] [-p PID] [-v] [-f] [duration]
#
# The current implementation uses an unrolled loop for x86_64, and was written
# as a proof of concept. This implementation should be replaced in the future
# with an appropriate bpf_ call, when available.
#
# Currently limited to a stack trace depth of 21 (maxdepth + 1).
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Jan-2016	Brendan Gregg	Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import signal

# arguments
examples = """examples:
    ./wakeuptime             # trace blocked time with waker stacks
    ./wakeuptime 5           # trace for 5 seconds only
    ./wakeuptime -f 5        # 5 seconds, and output in folded format
    ./wakeuptime -u          # don't include kernel threads (user only)
    ./wakeuptime -p 185      # trace fo PID 185 only
"""
parser = argparse.ArgumentParser(
    description="Summarize sleep to wakeup time by waker kernel stack",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-u", "--useronly", action="store_true",
    help="user threads only (no kernel threads)")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-v", "--verbose", action="store_true",
    help="show raw addresses")
parser.add_argument("-f", "--folded", action="store_true",
    help="output folded format")
parser.add_argument("duration", nargs="?", default=99999999,
    help="duration of trace, in seconds")
args = parser.parse_args()
folded = args.folded
duration = int(args.duration)
debug = 0
maxdepth = 20    # and MAXDEPTH
if args.pid and args.useronly:
    print("ERROR: use either -p or -u.")
    exit()

# signal handler
def signal_ignore(signal, frame):
    print()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAXDEPTH	20
#define MINBLOCK_US	1

struct key_t {
    char waker[TASK_COMM_LEN];
    char target[TASK_COMM_LEN];
    // Skip saving the ip
    u64 ret[MAXDEPTH];
};
BPF_HASH(counts, struct key_t);
BPF_HASH(start, u32);

static u64 get_frame(u64 *bp) {
    if (*bp) {
        // The following stack walker is x86_64/arm64 specific
        u64 ret = 0;
        if (bpf_probe_read(&ret, sizeof(ret), (void *)(*bp+8)))
            return 0;
        if (bpf_probe_read(bp, sizeof(*bp), (void *)*bp))
            return 0;
#ifdef __x86_64__
        if (ret < __START_KERNEL_map)
#elif __aarch64__
        if (ret < VA_START)
#else
#error "Unsupported architecture for stack walker"
#endif
            return 0;
        return ret;
    }
    return 0;
}

int offcpu(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    // XXX: should filter here too, but need task_struct
    start.update(&pid, &ts);
    return 0;
}

int waker(struct pt_regs *ctx, struct task_struct *p) {
    u32 pid = p->pid;
    u64 delta, *tsp, ts;

    tsp = start.lookup(&pid);
    if (tsp == 0)
        return 0;        // missed start
    start.delete(&pid);

    if (FILTER)
        return 0;

    // calculate delta time
    delta = bpf_ktime_get_ns() - *tsp;
    delta = delta / 1000;
    if (delta < MINBLOCK_US)
        return 0;

    struct key_t key = {};
    u64 zero = 0, *val, bp = 0;
    int depth = 0;

    bpf_probe_read(&key.target, sizeof(key.target), p->comm);
    bpf_get_current_comm(&key.waker, sizeof(key.waker));
    bp = PT_REGS_FP(ctx);

    // unrolled loop (MAXDEPTH):
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;

    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;

out:
    val = counts.lookup_or_init(&key, &zero);
    (*val) += delta;
    return 0;
}
"""
if args.pid:
    filter = 'pid != %s' % args.pid
elif args.useronly:
    filter = 'p->flags & PF_KTHREAD'
else:
    filter = '0'
bpf_text = bpf_text.replace('FILTER', filter)
if debug:
    print(bpf_text)

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="schedule", fn_name="offcpu")
b.attach_kprobe(event="try_to_wake_up", fn_name="waker")
matched = b.num_open_kprobes()
if matched == 0:
    print("0 functions traced. Exiting.")
    exit()

# header
if not folded:
    print("Tracing blocked time (us) by kernel stack", end="")
    if duration < 99999999:
        print(" for %d secs." % duration)
    else:
        print("... Hit Ctrl-C to end.")

# output
while (1):
    try:
        sleep(duration)
    except KeyboardInterrupt:
        # as cleanup can take many seconds, trap Ctrl-C:
        signal.signal(signal.SIGINT, signal_ignore)

    if not folded:
        print()
    counts = b.get_table("counts")
    for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
        if folded:
            # print folded stack output
            line = k.waker.decode('utf-8', 'replace') + ";"
            for i in reversed(range(0, maxdepth)):
                if k.ret[i] == 0:
                    continue
                line = line + b.ksym(k.ret[i])
                if i != 0:
                    line = line + ";"
            print("%s;%s %d" % (line, k.target.decode('utf-8', 'replace'), v.value))
        else:
            # print default multi-line stack output
            print("    %-16s %s" % ("target:", k.target.decode('utf-8', 'replace')))
            for i in range(0, maxdepth):
                if k.ret[i] == 0:
                    break
                print("    %-16x %s" % (k.ret[i],
                    b.ksym(k.ret[i])))
            print("    %-16s %s" % ("waker:", k.waker.decode('utf-8', 'replace')))
            print("        %d\n" % v.value)
    counts.clear()

    if not folded:
        print("Detaching...")
    exit()

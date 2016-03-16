#!/usr/bin/python
#
# offwaketime   Summarize blocked time by kernel off-CPU stack + waker stack
#               For Linux, uses BCC, eBPF.
#
# USAGE: offwaketime [-h] [-u] [-p PID] [-T] [duration]
#
# The current implementation uses an unrolled loop for x86_64, and was written
# as a proof of concept. This implementation should be replaced in the future
# with an appropriate bpf_ call, when available.
#
# The Off-CPU stack is currently limited to a stack trace depth of 20
# (maxtdepth), and the waker stack limited to 10 (maxwdepth). This is also
# limited to kernel stacks, and x86_64 only. Check for future versions, where
# these limitations should be removed.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 20-Jan-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep
import argparse
import signal

# arguments
examples = """examples:
    ./offwaketime             # trace off-CPU + waker stack time until Ctrl-C
    ./offwaketime 5           # trace for 5 seconds only
    ./offwaketime -f 5        # 5 seconds, and output in folded format
    ./offwaketime -u          # don't include kernel threads (user only)
    ./offwaketime -p 185      # trace fo PID 185 only
"""
parser = argparse.ArgumentParser(
    description="Summarize blocked time by kernel stack trace + waker stack",
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
maxwdepth = 10    # and MAXWDEPTH
maxtdepth = 20    # and MAXTDEPTH
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

#define MAXWDEPTH	10
#define MAXTDEPTH	20
#define MINBLOCK_US	1

struct key_t {
    char waker[TASK_COMM_LEN];
    char target[TASK_COMM_LEN];
    u64 wret[MAXWDEPTH];
    u64 tret[MAXTDEPTH];
};
BPF_HASH(counts, struct key_t);
BPF_HASH(start, u32);
struct wokeby_t {
    char name[TASK_COMM_LEN];
    u64 ret[MAXWDEPTH];
};
BPF_HASH(wokeby, u32, struct wokeby_t);

static u64 get_frame(u64 *bp) {
    if (*bp) {
        // The following stack walker is x86_64 specific
        u64 ret = 0;
        if (bpf_probe_read(&ret, sizeof(ret), (void *)(*bp+8)))
            return 0;
        if (bpf_probe_read(bp, sizeof(*bp), (void *)*bp))
            *bp = 0;
        if (ret < __START_KERNEL_map)
            return 0;
        return ret;
    }
    return 0;
}

int waker(struct pt_regs *ctx, struct task_struct *p) {
    u32 pid = p->pid;

    if (!(FILTER))
        return 0;

    u64 bp = 0;
    struct wokeby_t woke = {};
    int depth = 0;
    bpf_get_current_comm(&woke.name, sizeof(woke.name));
    bp = ctx->bp;

    // unrolled loop (MAXWDEPTH):
    if (!(woke.ret[depth++] = get_frame(&bp))) goto out;
    if (!(woke.ret[depth++] = get_frame(&bp))) goto out;
    if (!(woke.ret[depth++] = get_frame(&bp))) goto out;
    if (!(woke.ret[depth++] = get_frame(&bp))) goto out;
    if (!(woke.ret[depth++] = get_frame(&bp))) goto out;
    if (!(woke.ret[depth++] = get_frame(&bp))) goto out;
    if (!(woke.ret[depth++] = get_frame(&bp))) goto out;
    if (!(woke.ret[depth++] = get_frame(&bp))) goto out;
    if (!(woke.ret[depth++] = get_frame(&bp))) goto out;
    woke.ret[depth] = get_frame(&bp);

out:
    wokeby.update(&pid, &woke);
    return 0;
}

int oncpu(struct pt_regs *ctx, struct task_struct *p) {
    u32 pid = p->pid;
    u64 ts, *tsp;

    // record previous thread sleep time
    if (FILTER) {
        ts = bpf_ktime_get_ns();
        start.update(&pid, &ts);
    }

    // calculate current thread's delta time
    pid = bpf_get_current_pid_tgid();
    tsp = start.lookup(&pid);
    if (tsp == 0)
        return 0;        // missed start or filtered
    u64 delta = bpf_ktime_get_ns() - *tsp;
    start.delete(&pid);
    delta = delta / 1000;
    if (delta < MINBLOCK_US)
        return 0;

    // create map key
    u64 zero = 0, *val, bp = 0;
    int depth = 0;
    struct key_t key = {};
    struct wokeby_t *woke;
    bpf_get_current_comm(&key.target, sizeof(key.target));
    bp = ctx->bp;

    // unrolled loop (MAXTDEPTH):
    if (!(key.tret[depth++] = get_frame(&bp))) goto out;
    if (!(key.tret[depth++] = get_frame(&bp))) goto out;
    if (!(key.tret[depth++] = get_frame(&bp))) goto out;
    if (!(key.tret[depth++] = get_frame(&bp))) goto out;
    if (!(key.tret[depth++] = get_frame(&bp))) goto out;
    if (!(key.tret[depth++] = get_frame(&bp))) goto out;
    if (!(key.tret[depth++] = get_frame(&bp))) goto out;
    if (!(key.tret[depth++] = get_frame(&bp))) goto out;
    if (!(key.tret[depth++] = get_frame(&bp))) goto out;
    if (!(key.tret[depth++] = get_frame(&bp))) goto out;

    if (!(key.tret[depth++] = get_frame(&bp))) goto out;
    if (!(key.tret[depth++] = get_frame(&bp))) goto out;
    if (!(key.tret[depth++] = get_frame(&bp))) goto out;
    if (!(key.tret[depth++] = get_frame(&bp))) goto out;
    if (!(key.tret[depth++] = get_frame(&bp))) goto out;
    if (!(key.tret[depth++] = get_frame(&bp))) goto out;
    if (!(key.tret[depth++] = get_frame(&bp))) goto out;
    if (!(key.tret[depth++] = get_frame(&bp))) goto out;
    if (!(key.tret[depth++] = get_frame(&bp))) goto out;
    key.tret[depth] = get_frame(&bp);

out:
    woke = wokeby.lookup(&pid);
    if (woke) {
        __builtin_memcpy(&key.wret, woke->ret, sizeof(key.wret));
        __builtin_memcpy(&key.waker, woke->name, TASK_COMM_LEN);
        wokeby.delete(&pid);
    }

    val = counts.lookup_or_init(&key, &zero);
    (*val) += delta;
    return 0;
}
"""
if args.pid:
    filter = 'pid == %s' % args.pid
elif args.useronly:
    filter = '!(p->flags & PF_KTHREAD)'
else:
    filter = '1'
bpf_text = bpf_text.replace('FILTER', filter)
if debug:
    print(bpf_text)

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="finish_task_switch", fn_name="oncpu")
b.attach_kprobe(event="try_to_wake_up", fn_name="waker")
matched = b.num_open_kprobes()
if matched == 0:
    print("0 functions traced. Exiting.")
    exit()

# header
if not folded:
    print("Tracing blocked time (us) by kernel off-CPU and waker stack",
        end="")
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
            # fold target stack
            line = k.target + ";"
            for i in reversed(range(0, maxtdepth)):
                if k.tret[i] == 0:
                    continue
                line = line + b.ksym(k.tret[i])
                if i != 0:
                    line = line + ";"

            # add delimiter
            line = line + ";-"

            # fold waker stack
            for i in range(0, maxwdepth):
                line = line + ";"
                if k.wret[i] == 0:
                    break
                line = line + b.ksym(k.wret[i])
            if i != 0:
                line = line + ";" + k.waker

            # print as a line
            print("%s %d" % (line, v.value))
        else:
            # print wakeup name then stack in reverse order
            print("    %-16s %s" % ("waker:", k.waker))
            for i in reversed(range(0, maxwdepth)):
                if k.wret[i] == 0:
                    continue
                print("    %-16x %s" % (k.wret[i],
                    b.ksym(k.wret[i])))

            # print delimiter
            print("    %-16s %s" % ("-", "-"))

            # print default multi-line stack output
            for i in range(0, maxtdepth):
                if k.tret[i] == 0:
                    break
                print("    %-16x %s" % (k.tret[i],
                    b.ksym(k.tret[i])))
            print("    %-16s %s" % ("target:", k.target))
            print("        %d\n" % v.value)
    counts.clear()

    if not folded:
        print("Detaching...")
    exit()

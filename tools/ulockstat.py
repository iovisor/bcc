#!/usr/bin/env python
#
# ulockstat  Summarize user-space mutex lock contention, using USDT probes.
#
# USAGE: ulockstat [-h] [-d SECONDS | -i SECONDS] [-n COUNT] [-s DEPTH]
#                  [-m MIN_US] [-p PID] [-t TID]
#
# glibc's NPTL provides USDT probes for pthread mutexes. The interesting ones
# are mutex_entry (a thread is about to lock a mutex), mutex_acquired (the
# mutex was acquired) and mutex_release (the mutex is released). The time
# between mutex_entry and mutex_acquired is the time the thread spent waiting
# for the lock, and the time between mutex_acquired and mutex_release is the
# time the lock was held.
#
# These probes are documented in the glibc manual, "Debugging with the GNU C
# Library". Up to glibc 2.33 they use the "libpthread" provider; starting with
# glibc 2.34 the pthread code lives in libc and the provider is "libc". Both
# are handled here.
#
# glibc fires mutex_entry and mutex_acquired for every lock call, including
# the uncontended fast path, so by default the wait counts include those
# near-zero acquisitions too. Use -m to only count acquisitions that had to
# wait at least a given number of microseconds, which is the usual way to
# look at real contention. Hold times are always recorded, so the two blocks
# can have different counts.
#
# This tool can only report contention that occurs while it is running. It
# cannot report contention that happened before it was started. Since it
# instruments every lock and unlock, it may add noticeable overhead on a
# process with a high lock rate; use it for short investigations.
#
# Caveats: recursive mutexes re-lock without firing mutex_acquired, so their
# nested locks are not counted; and timed locks (pthread_mutex_timedlock) use
# separate probes and are not covered.
#
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 19-Sep-2026   Created this.

from __future__ import (
    absolute_import, division, unicode_literals, print_function
)

from bcc import BPF, USDT
import argparse
import errno
from time import sleep
import os
import sys

examples = """
    ulockstat                   # trace system wide, 1s refresh
    ulockstat -d 5              # trace for 5 seconds only
    ulockstat -i 5              # display stats every 5 seconds
    ulockstat -p 123            # trace user locks for PID 123
    ulockstat -t 1234           # trace user locks for TID 1234
    ulockstat -n 5 -s 3         # display 5 locks, 3 stack frames per lock
    ulockstat -m 1              # only count acquisitions that waited >= 1us
"""


def positive_int(val):
    try:
        ival = int(val)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")
    if ival < 0:
        raise argparse.ArgumentTypeError("must be positive")
    return ival


def positive_nonzero_int(val):
    ival = positive_int(val)
    if ival == 0:
        raise argparse.ArgumentTypeError("must be nonzero")
    return ival


parser = argparse.ArgumentParser(
    description="",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

time_group = parser.add_mutually_exclusive_group()
time_group.add_argument("-d", "--duration", type=positive_nonzero_int,
                        help="total duration of trace in seconds")
time_group.add_argument("-i", "--interval", type=positive_nonzero_int,
                        help="print summary at this interval (seconds)")
parser.add_argument("-n", "--locks", type=positive_nonzero_int,
                    default=99999999,
                    help="print this many top locks (default: all)")
parser.add_argument("-s", "--stacks", type=positive_nonzero_int,
                    default=1,
                    help="print this many stack frames per lock (default 1)")
parser.add_argument("-m", "--min-us", type=positive_int, default=0,
                    help="only record acquisitions that took at least this "
                         "many microseconds; useful to ignore the uncontended "
                         "fast path (default 0: record every acquisition)")
parser.add_argument("-p", "--pid", type=positive_int,
                    help="trace this PID only")
parser.add_argument("-t", "--tid", type=positive_int,
                    help="trace this TID only")
parser.add_argument("--stack-storage-size", default=16384,
                    type=positive_nonzero_int,
                    help="the number of unique stack traces that can be "
                         "stored and displayed (default 16384)")

args = parser.parse_args()

bpf_text = """
#include <uapi/linux/ptrace.h>

struct thread_mutex_key_t {
    u64 mtx;
    u32 tid;
    int stack_id;
};

struct thread_mutex_val_t {
    u32 pid;
    u64 wait_time_ns;
    u64 wait_count;
    u64 max_wait_ns;
    u64 hold_time_ns;
    u64 hold_count;
    u64 max_hold_ns;
};

// mutex a thread is currently trying to acquire: tid -> {mtx, timestamp}
struct entry_t {
    u64 mtx;
    u64 timestamp;
};

// mutex a thread currently holds: (tid, mtx) -> {timestamp, stack_id}
// The explicit pad field keeps the struct free of implicit padding, so the
// bytes used as a hash map key are always fully initialized.
struct lock_time_key_t {
    u64 mtx;
    u32 tid;
    u32 pad;
};

struct lock_time_val_t {
    u64 timestamp;
    int stack_id;
};

BPF_HASH(entry_start, u32, struct entry_t);
BPF_HASH(held_start, struct lock_time_key_t, struct lock_time_val_t);
BPF_HASH(locks, struct thread_mutex_key_t, struct thread_mutex_val_t);
BPF_STACK_TRACE(stacks, STACK_STORAGE_SIZE);

static inline int allowed(u64 pid_tgid) {
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    if (FILTER_PID && pid != FILTER_PID)
        return 0;
    if (FILTER_TID && tid != FILTER_TID)
        return 0;
    return 1;
}

// mutex_entry: about to try to acquire a mutex
int probe_mutex_entry(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    struct entry_t entry = {};

    if (!allowed(pid_tgid))
        return 0;

    bpf_usdt_readarg(1, ctx, &entry.mtx);
    entry.timestamp = bpf_ktime_get_ns();
    entry_start.update(&tid, &entry);
    return 0;
}

// mutex_acquired: the mutex was obtained
int probe_mutex_acquired(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    struct entry_t *entryp;
    struct thread_mutex_key_t key = {};
    struct thread_mutex_val_t zero = {}, *valp;
    struct lock_time_key_t hkey = {};
    struct lock_time_val_t hval = {};
    u64 now = bpf_ktime_get_ns();
    u64 wait_ns;

    if (!allowed(pid_tgid))
        return 0;

    entryp = entry_start.lookup(&tid);
    if (entryp == 0)
        return 0;   // missed the entry probe

    bpf_usdt_readarg(1, ctx, &key.mtx);
    wait_ns = now - entryp->timestamp;

    // A user stack walk is expensive, so it is only done for acquisitions
    // that had to wait at least min_ns. The uncontended fast path is a
    // handful of instructions and needs no stack: it is still accounted for
    // so that the hold time is complete, just without a stack id.
    key.tid = tid;
    if (wait_ns >= MIN_NS)
        // Attribute the wait to the stack that blocked, which is where the
        // contention is created.
        key.stack_id = stacks.get_stackid(ctx,
                        BPF_F_REUSE_STACKID | BPF_F_USER_STACK);
    else
        key.stack_id = -1;

    valp = locks.lookup_or_init(&key, &zero);
    if (valp != 0) {
        if (valp->pid == 0)
            valp->pid = pid_tgid >> 32;
        if (wait_ns >= MIN_NS) {
            valp->wait_time_ns += wait_ns;
            valp->wait_count += 1;
            if (wait_ns > valp->max_wait_ns)
                valp->max_wait_ns = wait_ns;
        }
    }

    hkey.tid = tid;
    hkey.mtx = key.mtx;
    hval.timestamp = now;
    hval.stack_id = key.stack_id;
    held_start.update(&hkey, &hval);

    entry_start.delete(&tid);
    return 0;
}

// mutex_release: the mutex is being released
int probe_mutex_release(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    struct lock_time_key_t hkey = {};
    struct lock_time_val_t *hvalp;
    struct thread_mutex_key_t key = {};
    struct thread_mutex_val_t *valp;
    u64 now = bpf_ktime_get_ns();
    u64 hold_ns;

    if (!allowed(pid_tgid))
        return 0;

    bpf_usdt_readarg(1, ctx, &hkey.mtx);
    hkey.tid = tid;

    hvalp = held_start.lookup(&hkey);
    if (hvalp == 0)
        return 0;   // missed the acquire probe

    hold_ns = now - hvalp->timestamp;

    key.mtx = hkey.mtx;
    key.tid = tid;
    key.stack_id = hvalp->stack_id;

    valp = locks.lookup(&key);
    if (valp != 0) {
        valp->hold_time_ns += hold_ns;
        valp->hold_count += 1;
        if (hold_ns > valp->max_hold_ns)
            valp->max_hold_ns = hold_ns;
    }

    held_start.delete(&hkey);
    return 0;
}
"""

if args.pid:
    bpf_text = bpf_text.replace("FILTER_PID", str(args.pid))
else:
    bpf_text = bpf_text.replace("FILTER_PID", "0")
if args.tid:
    bpf_text = bpf_text.replace("FILTER_TID", str(args.tid))
else:
    bpf_text = bpf_text.replace("FILTER_TID", "0")
bpf_text = bpf_text.replace("STACK_STORAGE_SIZE",
                            str(args.stack_storage_size))
bpf_text = bpf_text.replace("MIN_NS", str(args.min_us * 1000))

# libc and libpthread, depending on the glibc version, carry the USDT probes.
# Used for the system-wide (no -p/-t) case.
LIB_CANDIDATES = [
    "/lib/x86_64-linux-gnu/libc.so.6",
    "/usr/lib/x86_64-linux-gnu/libc.so.6",
    "/lib64/libc.so.6",
    "/usr/lib64/libc.so.6",
    "/lib/aarch64-linux-gnu/libc.so.6",
    "/lib/x86_64-linux-gnu/libpthread.so.0",
    "/usr/lib/x86_64-linux-gnu/libpthread.so.0",
    "/lib64/libpthread.so.0",
    "/lib/aarch64-linux-gnu/libpthread.so.0",
]


def find_libc_with_probes():
    for path in LIB_CANDIDATES:
        if not os.path.exists(path):
            continue
        try:
            usdt = USDT(path=path)
            for probe in usdt.enumerate_probes():
                if probe.name == b"mutex_entry":
                    return path
        except Exception:
            continue
    return None


def make_usdt():
    if args.pid:
        return USDT(pid=args.pid)
    if args.tid:
        return USDT(pid=args.tid)
    path = find_libc_with_probes()
    if not path:
        print("Error: could not find a libc/libpthread with USDT probes; "
              "use -p PID to trace a specific process", file=sys.stderr)
        sys.exit(1)
    return USDT(path=path)


def stack_id_err(stack_id):
    # -EFAULT in get_stackid normally means the stack trace is not available,
    # such as when unwinding a user stack from a kernel probe.
    return (stack_id < 0) and (stack_id != -errno.EFAULT)


def print_stacks(bpf, stack_id, depth, pid):
    if stack_id_err(stack_id):
        return
    resolved = 0
    for addr in bpf["stacks"].walk(stack_id):
        if resolved >= depth:
            break
        # bcc returns bytes, which would otherwise print as b'...'
        sym = bpf.sym(addr, pid, show_module=True, show_offset=True)
        print("  %s" % sym.decode("utf-8", "replace"))
        resolved += 1


def print_locks(bpf):
    locks = bpf["locks"]
    # Group by (pid, mutex): the same virtual address in two processes refers
    # to two different mutexes, so an address alone is not a valid identity.
    agg = {}
    for k, v in locks.items():
        pid = v.pid
        key = (pid, k.mtx)
        e = agg.setdefault(key, {
            "wait_time_ns": 0, "wait_count": 0, "max_wait_ns": 0,
            "hold_time_ns": 0, "hold_count": 0, "max_hold_ns": 0,
            "stacks": set(),
        })
        e["wait_time_ns"] += v.wait_time_ns
        e["wait_count"] += v.wait_count
        e["max_wait_ns"] = max(e["max_wait_ns"], v.max_wait_ns)
        e["hold_time_ns"] += v.hold_time_ns
        e["hold_count"] += v.hold_count
        e["max_hold_ns"] = max(e["max_hold_ns"], v.max_hold_ns)
        if k.stack_id >= 0 or k.stack_id == -errno.EFAULT:
            e["stacks"].add(k.stack_id)

    if not agg:
        print("No lock events collected yet.")
        return

    print("%8s %16s %10s %7s %10s %11s" %
          ("PID", "Mutex (hex)", "Avg Wait", "Count", "Max Wait",
           "Total Wait"))
    print("  %s" % ("-" * 68))
    by_wait = sorted(agg.items(), key=lambda kv: -kv[1]["wait_time_ns"])
    for (pid, mtx), e in by_wait[:args.locks]:
        if e["wait_count"] == 0:
            continue
        print("%8d %16x %10.1f %7d %10.1f %11.1f" %
              (pid, mtx, e["wait_time_ns"] / e["wait_count"] / 1000,
               e["wait_count"], e["max_wait_ns"] / 1000,
               e["wait_time_ns"] / 1000))
        # sorted() keeps the output stable across runs, since the stack ids
        # come from a set.
        for sid in sorted(e["stacks"]):
            print_stacks(bpf, sid, args.stacks, pid)

    print()
    print("%8s %16s %10s %7s %10s %11s" %
          ("PID", "Mutex (hex)", "Avg Hold", "Count", "Max Hold",
           "Total Hold"))
    print("  %s" % ("-" * 68))
    by_hold = sorted(agg.items(), key=lambda kv: -kv[1]["hold_time_ns"])
    for (pid, mtx), e in by_hold[:args.locks]:
        if e["hold_count"] == 0:
            continue
        print("%8d %16x %10.1f %7d %10.1f %11.1f" %
              (pid, mtx, e["hold_time_ns"] / e["hold_count"] / 1000,
               e["hold_count"], e["max_hold_ns"] / 1000,
               e["hold_time_ns"] / 1000))

    print()
    print("Times in us. Count is the number of lock acquisitions that had to "
          "wait; the stack below a mutex is the call site that blocked.")
    locks.clear()


def main():
    usdt = make_usdt()
    usdt.enable_probe("mutex_entry", "probe_mutex_entry")
    usdt.enable_probe("mutex_acquired", "probe_mutex_acquired")
    usdt.enable_probe("mutex_release", "probe_mutex_release")

    bpf = BPF(text=bpf_text, usdt_contexts=[usdt])

    if args.pid:
        print("Tracing user-space mutex events for PID %d..." % args.pid)
    elif args.tid:
        print("Tracing user-space mutex events for TID %d..." % args.tid)
    else:
        print("Tracing user-space mutex events system wide...")
    print("Hit Ctrl-C to end.")

    if args.duration:
        # A fixed duration prints a single summary at the end, like klockstat.
        try:
            sleep(args.duration)
        except KeyboardInterrupt:
            pass
        print()
        print_locks(bpf)
    else:
        interval = args.interval if args.interval else 1
        try:
            while True:
                sleep(interval)
                print()
                print_locks(bpf)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()

#!/usr/bin/env python
#
# pg_lwlocks    Time LWLocks in PostgreSQL and print wait/hold time
#               as a histogram. For Linux, uses BCC, eBPF.
#
# usage: pg_lwlocks BIN_PATH [-p PID] [-d]

from __future__ import print_function
from time import sleep
from bcc import BPF

import argparse
import ctypes as ct
import signal
import sys


text = """
#include <linux/ptrace.h>

typedef struct pg_atomic_uint32
{
    volatile unsigned int value;
} pg_atomic_uint32;

typedef struct LWLock
{
       unsigned short tranche;  /* tranche ID */
       pg_atomic_uint32 state;  /* state of exclusive/nonexclusive lockers */
} LWLock;

struct lwlock {
    u32 pid;
    u32 mode;
    u32 lock;
    bool missing;
    bool overwritten;
    bool deleted;
    bool wait;
    bool hold;
    u64 acquired;
    u64 released;
};

typedef enum LWLockMode
{
    LW_EXCLUSIVE,
    LW_SHARED,
    LW_WAIT_UNTIL_FREE	/* A special mode used in PGPROC->lwlockMode,
                         * when waiting for lock to become free. Not
                         * to be used as LWLockAcquire argument */
} LWLockMode;

#define HASH_SIZE 2^14

BPF_PERF_OUTPUT(events);

BPF_HASH(lock_hold, u32, struct lwlock, HASH_SIZE);
BPF_HASH(lock_wait, u32, struct lwlock, HASH_SIZE);

// Histogram of lock hold times
BPF_HISTOGRAM(lock_hold_shared_hist, u64);
BPF_HISTOGRAM(lock_hold_exclusive_hist, u64);

// Histogram of lock wait times
BPF_HISTOGRAM(lock_wait_shared_hist, u64);
BPF_HISTOGRAM(lock_wait_exclusive_hist, u64);

void probe_lwlock_acquire_start(struct pt_regs *ctx,
                                struct LWLock *lock, int mode)
{
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    struct lwlock data = {};
    data.mode = mode;
    data.acquired = now;
    data.pid = pid;
    data.released = 0;
    data.lock = (u32) lock;
    data.wait = true;

    struct lwlock *test = lock_wait.lookup(&pid);
    if (test != NULL)
    {
        test->overwritten = true;
        events.perf_submit(ctx, test, sizeof(*test));
    }
    else
    {
        events.perf_submit(ctx, &data, sizeof(data));
        lock_wait.update(&pid, &data);
    }
}

void probe_lwlock_acquire_finish(struct pt_regs *ctx)
{
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    struct lwlock data = {};
    struct lwlock *wait_data = lock_wait.lookup(&pid);

    if (wait_data != NULL)
    {
        u64 timestamp = now;
        u64 wait_time = timestamp - wait_data->acquired;
        u64 lwlock_slot = bpf_log2l(wait_time / 1000);

        wait_data->released = timestamp;
        data.mode = wait_data->mode;
        data.lock = wait_data->lock;

        switch (wait_data->mode)
        {
            case LW_EXCLUSIVE:
                lock_wait_exclusive_hist.increment(lwlock_slot);
                break;
            case LW_SHARED:
                lock_wait_shared_hist.increment(lwlock_slot);
                break;
            default:
                break;
        }

        wait_data->deleted = true;
        events.perf_submit(ctx, wait_data, sizeof(*wait_data));
        lock_wait.delete(&pid);
    }
    else
    {
        // can't determine the mode, skip
        return;
    }

    data.acquired = now;
    data.pid = pid;
    data.released = 0;
    data.hold = true;

    struct lwlock *test = lock_hold.lookup(&pid);
    if (test != NULL)
    {
        test->overwritten = true;
        events.perf_submit(ctx, test, sizeof(*test));
    }
    else
    {
        events.perf_submit(ctx, &data, sizeof(data));
        lock_hold.update(&pid, &data);
    }
}

void probe_lwlock_release(struct pt_regs *ctx, struct LWLock *lock)
{
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    struct lwlock *data = lock_hold.lookup(&pid);

    if (data == NULL)
    {
        struct lwlock hold_data = {};
        hold_data.pid = pid;
        hold_data.lock = (u32) lock;
        hold_data.hold = true;
        hold_data.missing = true;

        events.perf_submit(ctx, &hold_data, sizeof(hold_data));
        return;
    }

    u64 hold_time = now - data->acquired;
    data->released = now;

    u64 lwlock_slot = bpf_log2l(hold_time / 1000);
    switch (data->mode)
    {
        case LW_EXCLUSIVE:
            lock_hold_exclusive_hist.increment(lwlock_slot);
            break;
        case LW_SHARED:
            lock_hold_shared_hist.increment(lwlock_slot);
            break;
        default:
            break;
    }

    data->deleted = true;
    events.perf_submit(ctx, data, sizeof(*data));
    lock_hold.delete(&pid);
}
"""


def attach(bpf, binary_path, pid=-1):
    bpf.attach_uprobe(
        name=binary_path,
        sym="LWLockAcquire",
        fn_name="probe_lwlock_acquire_start",
        pid=pid)
    bpf.attach_uretprobe(
        name=binary_path,
        sym="LWLockAcquire",
        fn_name="probe_lwlock_acquire_finish",
        pid=pid)

    bpf.attach_uprobe(
        name=binary_path,
        sym="LWLockAcquireOrWait",
        fn_name="probe_lwlock_acquire_start",
        pid=pid)
    bpf.attach_uretprobe(
        name=binary_path,
        sym="LWLockAcquireOrWait",
        fn_name="probe_lwlock_acquire_finish",
        pid=pid)

    bpf.attach_uprobe(
        name=binary_path,
        sym="LWLockRelease",
        fn_name="probe_lwlock_release",
        pid=pid)


# signal handler
def signal_ignore(signal, frame):
    print()


class Data(ct.Structure):
    _fields_ = [("pid", ct.c_uint32),
                ("mode", ct.c_uint32),
                ("lock", ct.c_uint32),
                ("missing", ct.c_bool),
                ("overwritten", ct.c_bool),
                ("deleted", ct.c_bool),
                ("wait", ct.c_bool),
                ("hold", ct.c_bool),
                ("acquired", ct.c_uint64),
                ("released", ct.c_uint64)]


def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    prefix = None

    if event.missing:
        prefix = "Missing"
    if event.overwritten:
        prefix = "Overwritten"
    if event.deleted:
        prefix = "About to delete"

    if event.hold and prefix is not None:
        prefix += " hold"
    if event.wait and prefix is not None:
        prefix += " wait"

    if event.hold and prefix is None:
        prefix = "Hold"
    if event.wait and prefix is None:
        prefix = "Wait"

    print("{} event: acquired {} released {} pid {} mode {} lock {}".format(
        prefix or "",
        event.acquired,
        event.released,
        event.pid,
        event.mode,
        event.lock))


def run(args):
    print("Attaching...")
    debug = 4 if args.debug else 0
    bpf = BPF(text=text, debug=debug)
    attach(bpf, args.path, args.pid)
    lock_hold_exclusive_hist = bpf["lock_hold_exclusive_hist"]
    lock_hold_shared_hist = bpf["lock_hold_shared_hist"]
    lock_wait_exclusive_hist = bpf["lock_wait_exclusive_hist"]
    lock_wait_shared_hist = bpf["lock_wait_shared_hist"]
    exiting = False

    if args.debug:
        bpf["events"].open_perf_buffer(print_event)

    print("Listening...")
    while True:
        try:
            sleep(1)
            if args.debug:
                bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            exiting = True
            # as cleanup can take many seconds, trap Ctrl-C:
            signal.signal(signal.SIGINT, signal_ignore)

        if exiting:
            print("Detaching...")
            break

    print("Exclusive lock holding time")
    lock_hold_exclusive_hist.print_log2_hist("hold time (us)")
    print("")

    print("Shared lock holding time")
    lock_hold_shared_hist.print_log2_hist("hold time (us)")
    print("")

    print("Exclusive lock waiting time")
    lock_wait_exclusive_hist.print_log2_hist("wait time (us)")
    print("")

    print("Shared lock waiting time")
    lock_wait_shared_hist.print_log2_hist("wait time (us)")
    print("")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Time LWLocks in PostgreSQL",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", type=str, help="path to target binary")
    parser.add_argument("-p", "--pid", type=int, default=-1,
            help="trace this PID only")
    parser.add_argument("-d", "--debug", action='store_true', default=False,
            help="debug mode")

    return parser.parse_args()


if __name__ == "__main__":
    run(parse_args())

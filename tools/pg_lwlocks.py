#!/usr/bin/env python

import sys
from time import sleep
from bcc import BPF
import signal
import ctypes as ct

text = """
#include <linux/ptrace.h>

typedef struct pg_atomic_uint32
{
    volatile unsigned int value;
} pg_atomic_uint32;

typedef struct LWLock
{
       unsigned short tranche;         /* tranche ID */
       pg_atomic_uint32 state;         /* state of exclusive/nonexclusive lockers */
} LWLock;

struct lwlock {
    u32 pid;
    int mode;
    u64 acquired;
    u64 released;
};

struct message {
    char text[100];
};

typedef enum LWLockMode
{
    LW_EXCLUSIVE,
    LW_SHARED,
    LW_WAIT_UNTIL_FREE	/* A special mode used in PGPROC->lwlockMode,
                         * when waiting for lock to become free. Not
                         * to be used as LWLockAcquire argument */
} LWLockMode;

BPF_PERF_OUTPUT(events);
BPF_PERF_OUTPUT(messages);

BPF_HASH(lock_hold, u32, struct lwlock);
BPF_HASH(lock_wait, u32, struct lwlock);

// Histogram of lock hold times
BPF_HISTOGRAM(lock_hold_shared_hist, u64);
BPF_HISTOGRAM(lock_hold_exclusive_hist, u64);

// Histogram of lock wait times
BPF_HISTOGRAM(lock_wait_shared_hist, u64);
BPF_HISTOGRAM(lock_wait_exclusive_hist, u64);

void probe_lwlock_acquire_start(struct pt_regs *ctx, struct LWLock *lock, int mode)
{
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    struct lwlock data = {};
    data.mode = mode;
    data.acquired = now;
    data.pid = pid;
    data.released = 0;

    events.perf_submit(ctx, &data, sizeof(data));
    struct lwlock *test = lock_wait.lookup(&pid);
    if (test != 0)
    {
        struct message msg = {};
        strcpy(msg.text, "Lock is overwritten");
        messages.perf_submit(ctx, &msg, sizeof(msg));
    }

    lock_wait.update(&pid, &data);
}

void probe_lwlock_acquire_finish(struct pt_regs *ctx, struct LWLock *lock, int mode)
{
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    struct lwlock data = {};
    struct lwlock *wait_data = lock_wait.lookup(&pid);

    if (wait_data != 0)
    {
        u64 wait_time = now - wait_data->acquired;
        u64 lwlock_slot = bpf_log2l(wait_time / 1000);
        switch (mode)
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
        lock_wait.delete(&pid);
    }

    data.mode = mode;
    data.acquired = now;
    data.pid = pid;
    data.released = 0;

    events.perf_submit(ctx, &data, sizeof(data));
    struct lwlock *test = lock_hold.lookup(&pid);
    if (test != 0)
    {
        struct message msg = {};
        strcpy(msg.text, "Lock is overwritten");
        messages.perf_submit(ctx, &msg, sizeof(msg));
    }

    lock_hold.update(&pid, &data);
}

void probe_lwlock_release(struct pt_regs *ctx, struct LWLock *lock)
{
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    struct lwlock *data = lock_hold.lookup(&pid);
    if (data == 0)
    {
        struct message msg = {};
        strcpy(msg.text, "Lock is missing");
        messages.perf_submit(ctx, &msg, sizeof(msg));
        return;
    }

    u64 hold_time = now - data->acquired;
    data->released = now;

    events.perf_submit(ctx, data, sizeof(*data));
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
    lock_hold.delete(&pid);
}
"""


def attach(bpf, binary_path):
    bpf.attach_uprobe(name=binary_path, sym="LWLockAcquire", fn_name="probe_lwlock_acquire_start")
    bpf.attach_uretprobe(name=binary_path, sym="LWLockAcquire", fn_name="probe_lwlock_acquire_finish")

    bpf.attach_uprobe(name=binary_path, sym="LWLockAcquireOrWait", fn_name="probe_lwlock_acquire_start")
    bpf.attach_uretprobe(name=binary_path, sym="LWLockAcquireOrWait", fn_name="probe_lwlock_acquire_finish")

    bpf.attach_uprobe(name=binary_path, sym="LWLockRelease", fn_name="probe_lwlock_release")


# signal handler
def signal_ignore(signal, frame):
    print()


class Data(ct.Structure):
    _fields_ = [("pid", ct.c_ulong),
                ("mode", ct.c_int),
                ("acquired", ct.c_ulonglong),
                ("released", ct.c_ulonglong)]


class Message(ct.Structure):
    _fields_ = [("text", ct.c_char * 100)]


def print_messages(cpu, data, size):
    msg = ct.cast(data, ct.POINTER(Message)).contents
    print(msg.text)


def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print("Event: acquired {} released {} pid {}".format(
        event.acquired, event.released, event.pid))


def run(binary_path, debug=False):
    print("Attaching...")
    bpf = BPF(text=text)
    attach(bpf, binary_path)
    lock_hold_exclusive_hist = bpf["lock_hold_exclusive_hist"]
    lock_hold_shared_hist = bpf["lock_hold_shared_hist"]
    lock_wait_exclusive_hist = bpf["lock_wait_exclusive_hist"]
    lock_wait_shared_hist = bpf["lock_wait_shared_hist"]
    exiting = False

    if debug:
        bpf["events"].open_perf_buffer(print_event)
        bpf["messages"].open_perf_buffer(print_messages)

    print("Listening...")
    while True:
        try:
            sleep(1)
            if debug:
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


if __name__ == "__main__":
    run(sys.argv[1])

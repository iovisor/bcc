#!/usr/bin/env python3.6

import sys
import itertools
from time import sleep
from bcc import BPF
import signal

text = """
#include <linux/ptrace.h>

struct lwlock {
    u32 pid;
    int mode;
    u64 timestamp;
};

BPF_HASH(locks, struct LWLock *, struct lwlock);

// Histogram of lock hold times
BPF_HISTOGRAM(lwlock_hold, u64);

void probe_lwlock_acquire(struct pt_regs *ctx, struct LWLock *lock, int mode)
{
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    struct lwlock data = {};
    data.mode = mode;
    data.timestamp = now;
    data.pid = pid;
    locks.update(&lock, &data);
}

void probe_lwlock_release(struct pt_regs *ctx, struct LWLock *lock)
{
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    struct lwlock *data = locks.lookup(&lock);
    if (data == 0 || data->timestamp == 0)
        return;

    u64 hold_time = now - data->timestamp;
    u64 lwlock_slot = bpf_log2l(hold_time / 1000);
    lwlock_hold.increment(lwlock_slot);
    locks.delete(&lock);
}
"""

BINARY = "/home/erthalion/build/postgresql-master/bin/postgres"

def attach(bpf, binary_path):
    bpf.attach_uprobe(name=binary_path, sym="LWLockAcquire", fn_name="probe_lwlock_acquire")
    bpf.attach_uprobe(name=binary_path, sym="LWLockRelease", fn_name="probe_lwlock_release")

# signal handler
def signal_ignore(signal, frame):
    print()

def run(binary_path=BINARY):
    bpf = BPF(text=text)
    attach(bpf, binary_path)
    lwlock_hold = bpf["lwlock_hold"]
    exiting = False

    while True:
        try:
            sleep(1)
        except KeyboardInterrupt:
            exiting = True
            # as cleanup can take many seconds, trap Ctrl-C:
            signal.signal(signal.SIGINT, signal_ignore)

        if exiting:
            print("Detaching...")
            break

    lwlock_hold.print_log2_hist(val_type="wait time (us)")

if __name__ == "__main__":
    run(sys.argv[1])

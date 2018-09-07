#!/usr/bin/env python
#
# pg_spin_locks    Time spin locks in PostgreSQL and print wait time
#                  as a histogram. For Linux, uses BCC, eBPF.
#
# usage: pg_spin_locks BIN_PATH [-p PID] [-d]

from __future__ import print_function
from time import sleep
from bcc import BPF

import argparse
import ctypes as ct
import signal
import sys


text = """
#include <linux/ptrace.h>

struct spin_lock {
    u32 pid;
    u64 acquired;
    u64 released;
};

struct message {
    char text[100];
};

typedef unsigned char slock_t;

BPF_PERF_OUTPUT(events);
BPF_PERF_OUTPUT(messages);

BPF_HASH(lock_wait, u32, struct spin_lock);

// Histogram of lock wait times
BPF_HISTOGRAM(lock_wait_hist, u64);

void probe_spin_lock_wait_start(struct pt_regs *ctx, volatile slock_t *lock, const char *file, int line, const char *func)
{
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    struct spin_lock data = {};
    data.acquired = now;
    data.pid = pid;
    data.released = 0;

    events.perf_submit(ctx, &data, sizeof(data));
    struct spin_lock *test = lock_wait.lookup(&pid);
    if (test != 0)
    {
        struct message msg = {};
        strcpy(msg.text, "Lock is overwritten");
        messages.perf_submit(ctx, &msg, sizeof(msg));
    }

    lock_wait.update(&pid, &data);
}

void probe_spin_lock_wait_finish(struct pt_regs *ctx, volatile slock_t *lock, const char *file, int line, const char *func)
{
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    struct spin_lock *wait_data = lock_wait.lookup(&pid);

    if (wait_data == 0)
    {
        struct message msg = {};
        strcpy(msg.text, "Lock is missing");
        messages.perf_submit(ctx, &msg, sizeof(msg));
        return;
    }

    u64 wait_time = now - wait_data->acquired;
    u64 spin_lock_slot = bpf_log2l(wait_time / 1000);
    lock_wait_hist.increment(spin_lock_slot);
    lock_wait.delete(&pid);
}
"""


def attach(bpf, binary_path, pid=-1):
    bpf.attach_uprobe(
        name=binary_path,
        sym="s_lock",
        fn_name="probe_spin_lock_wait_start",
        pid=pid)
    bpf.attach_uretprobe(
        name=binary_path,
        sym="s_lock",
        fn_name="probe_spin_lock_wait_finish",
        pid=pid)


# signal handler
def signal_ignore(signal, frame):
    print()


class Data(ct.Structure):
    _fields_ = [("pid", ct.c_ulong),
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


def run(args):
    print("Attaching...")
    bpf = BPF(text=text)
    attach(bpf, args.path, args.pid)
    lock_wait_hist = bpf["lock_wait_hist"]
    exiting = False

    if args.debug:
        bpf["events"].open_perf_buffer(print_event)
        bpf["messages"].open_perf_buffer(print_messages)

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

    print("Spin lock waiting time")
    lock_wait_hist.print_log2_hist("wait time (us)")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Time spin locks in PostgreSQL",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", type=str, help="path to target binary")
    parser.add_argument("-p", "--pid", type=int, default=-1,
            help="trace this PID only")
    parser.add_argument("-d", "--debug", action='store_true', default=False,
            help="debug mode")

    return parser.parse_args()


if __name__ == "__main__":
    run(parse_args())

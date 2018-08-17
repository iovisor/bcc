#!/usr/bin/env python

import sys
from time import sleep
from bcc import BPF
import signal
import ctypes as ct

text = """
#include <linux/ptrace.h>

struct pg_semaphore {
    u32 pid;
    u64 acquired;
    u64 released;
};

struct message {
    char text[100];
};

BPF_PERF_OUTPUT(events);
BPF_PERF_OUTPUT(messages);

BPF_HASH(lock_hold, u32, struct pg_semaphore);
BPF_HASH(lock_wait, u32, struct pg_semaphore);

// Histogram of semaphore hold times
BPF_HISTOGRAM(lock_hold_semaphore_hist, u64);

// Histogram of semaphore wait times
BPF_HISTOGRAM(lock_wait_semaphore_hist, u64);

void probe_semaphore_lock_start(struct pt_regs *ctx)
{
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    struct pg_semaphore data = {};
    data.acquired = now;
    data.pid = pid;
    data.released = 0;

    events.perf_submit(ctx, &data, sizeof(data));
    struct pg_semaphore *test = lock_wait.lookup(&pid);
    if (test != 0)
    {
        struct message msg = {};
        strcpy(msg.text, "Semaphore is overwritten");
        messages.perf_submit(ctx, &msg, sizeof(msg));
    }

    lock_wait.update(&pid, &data);
}

void probe_semaphore_lock_finish(struct pt_regs *ctx)
{
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    struct pg_semaphore data = {};
    struct pg_semaphore *wait_data = lock_wait.lookup(&pid);

    if (wait_data != 0)
    {
        u64 wait_time = now - wait_data->acquired;
        u64 semaphore_slot = bpf_log2l(wait_time / 1000);
        lock_wait_semaphore_hist.increment(semaphore_slot);
        lock_wait.delete(&pid);
    }

    data.acquired = now;
    data.pid = pid;
    data.released = 0;

    events.perf_submit(ctx, &data, sizeof(data));
    struct pg_semaphore *test = lock_hold.lookup(&pid);
    if (test != 0)
    {
        struct message msg = {};
        strcpy(msg.text, "Semaphore is overwritten");
        messages.perf_submit(ctx, &msg, sizeof(msg));
    }

    lock_hold.update(&pid, &data);
}

void probe_semaphore_unlock(struct pt_regs *ctx)
{
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    struct pg_semaphore *data = lock_hold.lookup(&pid);
    if (data == 0)
    {
        struct message msg = {};
        strcpy(msg.text, "Semaphore is missing");
        messages.perf_submit(ctx, &msg, sizeof(msg));
        return;
    }

    u64 hold_time = now - data->acquired;
    data->released = now;

    events.perf_submit(ctx, data, sizeof(*data));
    u64 semaphore_slot = bpf_log2l(hold_time / 1000);
    lock_hold_semaphore_hist.increment(semaphore_slot);
    lock_hold.delete(&pid);
}
"""


def attach(bpf, binary_path):
    bpf.attach_uprobe(name=binary_path, sym="PGSemaphoreLock", fn_name="probe_semaphore_lock_start")
    bpf.attach_uretprobe(name=binary_path, sym="PGSemaphoreLock", fn_name="probe_semaphore_lock_finish")

    bpf.attach_uprobe(name=binary_path, sym="PGSemaphoreUnlock", fn_name="probe_semaphore_unlock")


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
    lock_hold_semaphore_hist = bpf["lock_hold_semaphore_hist"]
    lock_wait_semaphore_hist = bpf["lock_wait_semaphore_hist"]
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

    print("Semaphore holding time")
    lock_hold_semaphore_hist.print_log2_hist("hold time (us)")
    print("")

    print("Semaphore waiting time")
    lock_wait_semaphore_hist.print_log2_hist("wait time (us)")
    print("")


if __name__ == "__main__":
    run(sys.argv[1])

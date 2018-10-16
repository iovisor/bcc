#!/usr/bin/env python
#
# pg_futex   Display size of hash buckets that are used for futexes (and
#            transitively for PGSemathore). For Linux, uses BCC, eBPF.
#
# usage: pg_futex [-p PID] [-d]


from __future__ import print_function
from time import sleep
from bcc import BPF

import argparse
import ctypes as ct
import signal
import sys


text = """
#include <linux/ptrace.h>

struct futex_hash_bucket {
	atomic_t waiters;
	spinlock_t lock;
	struct plist_head chain;
};

union futex_key {
	struct {
		unsigned long pgoff;
		struct inode *inode;
		int offset;
	} shared;
	struct {
		unsigned long address;
		struct mm_struct *mm;
		int offset;
	} private;
	struct {
		unsigned long word;
		void *ptr;
		int offset;
	} both;
};

struct futex_q {
	struct plist_node list;

	struct task_struct *task;
	spinlock_t *lock_ptr;
	union futex_key key;
	struct futex_pi_state *pi_state;
	struct rt_mutex_waiter *rt_waiter;
	union futex_key *requeue_pi_key;
	u32 bitset;
};

struct futex_data {
    u32 pid;
    u64 timestamp;
    u32 hash_bucket;
    char name[16];
};

BPF_PERF_OUTPUT(events);

#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:        the pointer to the member.
 * @type:       the type of the container struct this is embedded in.
 * @member:     the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({                      \
	const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
	(type *)( (char *)__mptr - offsetof(type,member) );})

void probe_unqueue_futex(struct pt_regs *ctx)
{
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct futex_q futex_q_tmp = {};
    struct futex_hash_bucket futex_hash_bucket_tmp = {};
    struct futex_hash_bucket *hb;
    struct futex_data data = {};
    bpf_probe_read(&data.name, 16, &task->comm);
    data.timestamp = now;
    data.pid = pid;
    bpf_probe_read(&futex_q_tmp,
                    sizeof(futex_q_tmp),
                    ((struct futex_q *)PT_REGS_PARM1(ctx)));
    hb = container_of(futex_q_tmp.lock_ptr, struct futex_hash_bucket, lock);
    bpf_probe_read(&futex_hash_bucket_tmp,
                    sizeof(futex_hash_bucket_tmp),
                    ((struct futex_hash_bucket *)hb));
    data.hash_bucket = (u32) futex_hash_bucket_tmp.waiters.counter;

    if (data.hash_bucket > 3)
        events.perf_submit(ctx, &data, sizeof(data));
}
"""


def attach(bpf):
    bpf.attach_kprobe(
        event="__unqueue_futex",
        fn_name="probe_unqueue_futex")


# signal handler
def signal_ignore(signal, frame):
    print()


class Data(ct.Structure):
    _fields_ = [("pid", ct.c_ulong),
                ("timestamp", ct.c_ulonglong),
                ("hash_bucket", ct.c_uint32),
                ("name", ct.c_char * 10)]


def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print("Event: timestamp {} pid {} hash_bucket {}, name {}".format(
        event.timestamp, event.pid, event.hash_bucket, event.name))


def run(args):
    print("Attaching...")
    debug = 4 if args.debug else 0
    bpf = BPF(text=text, debug=debug)
    attach(bpf)
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


def parse_args():
    parser = argparse.ArgumentParser(
        description="Hash bucket size for futexes",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-p", "--pid", type=int, default=-1,
            help="trace this PID only")
    parser.add_argument("-d", "--debug", action='store_true', default=False,
            help="debug mode")

    return parser.parse_args()


if __name__ == "__main__":
    run(parse_args())

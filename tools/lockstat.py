#!/usr/bin/env bcc-py
#
# lockstat Trace and display lock contention stats
#
# USAGE: lockstat

# Licensed under the Apache License, Version 2.0 (the "License")
# 28-Jul-2017   Gisle Dankel   Created this.

from bcc import BPF
from ctypes import c_int
from time import sleep
from datetime import datetime
import argparse
import subprocess
import os

class Lock(object):
    def __init__(self):
        self.contention_count = 0
        self.elapsed_blocked = 0
        self.thread_count = 0

    def update(self, count, block_time):
        self.contention_count += count
        self.elapsed_blocked += block_time
        self.thread_count += 1


examples = """
EXAMPLES:

./lockstat
        Trace calls to sys_futex and display contented locks every 5 seconds
        for all processes running on the system
./lockstat -p <pid>
        Trace only for the specified pid and display contended locks
        every 5 seconds
./lockstat -p <pid> -t
        Trace for a specified pid and print a message on each entry and exit to
        sys_futex
./lockstat -p <pid> 10
        Trace the specified pid and show a message every 10 seconds
./lockstat -c <command> 1 30
        Run the specified command and display contended locks every 1 second
        for a total of 30 times
"""

description = """
Trace kernel futex events.
These often occur because of lock contention, e.g. involving a pthread_mutex.
This script resemblers the following SystemTap example:
https://sourceware.org/systemtap/SystemTap_Beginners_Guide/futexcontentionsect.html
"""

parser = argparse.ArgumentParser(description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
parser.add_argument("-p", "--pid", type=int, default=-1,
        help="the PID to trace; if not specified, trace all")
parser.add_argument("-t", "--trace", action="store_true",
        help="print trace messages for each futex enter/exit")
parser.add_argument("interval", nargs="?", default=5, type=int,
        help="interval in seconds to print summary")
parser.add_argument("count", nargs="?", type=int,
        help="number of times to print the report before exiting")
parser.add_argument("-c", "--command",
        help="execute and trace the specified command")

args = parser.parse_args()

pid = args.pid
command = args.command
interval = args.interval
num_prints = args.count
trace_all = args.trace

if command is not None:
        print("Executing '%s' and tracing the resulting process." % command)
        pid = run_command_get_pid(command)

bpf_source = """
#include <uapi/linux/futex.h>
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/time.h>

struct comm_t {
    char name[TASK_COMM_LEN];
};

struct lock_key_t {
        u64 uaddr;
        u32 pid;
        u32 tgid;
};

struct lock_info_t {
        u64 elapsed_blocked;
        u64 contention_count;
};


BPF_HASH(pid_lock, u32, u64);
BPF_HASH(pid_blocktime, u32, u64);
BPF_HASH(tgid_comm, u32, struct comm_t);
BPF_HASH(lock_stats, struct lock_key_t, struct lock_info_t, 1000000);

static inline int update_stats(u64 pid_tgid, u64 uaddr, u64 block_time) {
        struct lock_key_t key = {};
        struct lock_info_t zero = {};
        struct lock_info_t *info;

        u32 pid = pid_tgid;
        u32 tgid = (pid_tgid >> 32);
        key.pid = pid;
        key.tgid = tgid;
        key.uaddr = uaddr;
        info = lock_stats.lookup_or_init(&key, &zero);
        info->elapsed_blocked += block_time;
        info->contention_count++;

        if (0 == tgid_comm.lookup(&tgid)) {
            struct comm_t comm;
            bpf_get_current_comm(&comm.name, sizeof(comm.name));
            tgid_comm.update(&tgid, &comm);
        }
        return 0;
}

// FIXME: Should attach to sys_enter_futex and sys_exit_futex tracepoints here,
// but that does not currently work
int sys_futex_enter(struct pt_regs *ctx, u32 *uaddr, int op, u32 val,
                    struct timespec *utime, u32 *uaddr2, u32 val3) {
        int cmd = op & FUTEX_CMD_MASK;
        if (cmd != FUTEX_WAIT)
                return 0;

        u32 pid = bpf_get_current_pid_tgid();
        u64 timestamp = bpf_ktime_get_ns();
        u64 uaddr64 = (u64) uaddr;
        pid_lock.update(&pid, &uaddr64);
        pid_blocktime.update(&pid, &timestamp);

        if (SHOULD_PRINT)
                bpf_trace_printk("enter sys_futex, pid = %u, uaddr = %u, "
                                 "cmd = %u\\n", pid, uaddr64, cmd);
        return 0;
}

int sys_futex_exit(struct pt_regs *ctx) {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid;
        u64 *blocktime = pid_blocktime.lookup(&pid);
        u64 *uaddr = pid_lock.lookup(&pid);
        u64 timestamp = bpf_ktime_get_ns();
        u64 elapsed;

        if (blocktime == 0 || uaddr == 0)
                return 0; // not FUTEX_WAIT, or (less likely) missed futex_enter

        elapsed = timestamp - *blocktime;
        update_stats(pid_tgid, *uaddr, elapsed);
        pid_lock.delete(&pid);
        pid_blocktime.delete(&pid);

        if (SHOULD_PRINT) {
                bpf_trace_printk("exit sys_futex, uaddr = %u, elapsed = %uns\\n",
                                 uaddr == 0 ? 0 : *uaddr, elapsed);
        }
        return 0;
}

"""

bpf_source = bpf_source.replace("SHOULD_PRINT", "1" if trace_all else "0")

bpf_program = BPF(text=bpf_source)

print("Attaching to pid %d, Ctrl+C to quit." % pid)

bpf_program.attach_kprobe(event="SyS_futex", fn_name="sys_futex_enter", pid=pid)
bpf_program.attach_kretprobe(event="SyS_futex", fn_name="sys_futex_exit", pid=pid)

def create_tgid_stats():
        stats = bpf_program["lock_stats"]
        res = {}
        for key, val in stats.items():
                if not key.tgid in res:
                        res[key.tgid] = {}
                if not key.uaddr in res[key.tgid]:
                        res[key.tgid][key.uaddr] = Lock()
                lock = res[key.tgid][key.uaddr]
                lock.update(val.contention_count, val.elapsed_blocked)
        return res

def print_comm_stats(stats):
        comms = bpf_program["tgid_comm"]
        print("\n%s:" % (datetime.now().strftime("%H:%M:%S")))
        for tgid, locks in stats.items():
                comm = comms[c_int(tgid)].name
                print("\n  %s (%d):" % (comm, tgid))
                sorted_locks = sorted(locks.items(),
                                      key=lambda x: x[1].elapsed_blocked,
                                      reverse=True)
                for addr, stats in sorted_locks:
                    print("    %x: %dms (%d contentions affected %d threads)" %
                          (addr, stats.elapsed_blocked / 1000000,
                           stats.contention_count, stats.thread_count))

count_so_far = 0
while True:
        if trace_all:
                print(bpf_program.trace_fields())
        else:
                try:
                        sleep(interval)
                except KeyboardInterrupt:
                        exit()
                print_comm_stats(create_tgid_stats())
                count_so_far += 1
                bpf_program['tgid_comm'].clear()
                bpf_program['lock_stats'].clear()
                bpf_program['pid_lock'].clear()
                bpf_program['pid_blocktime'].clear()

                if num_prints is not None and count_so_far >= num_prints:
                        exit()

#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# cpuload   Display top N tasks use more than U percent cpu resource when
#           the cpu doesn't enter idle state for more than T ns.
#
# USAGE: cpuload [-h] [-t time] [-n number] [-u usage] [-c cpumask]
#
# This uses in-kernel eBPF maps to cache task details (PID and comm) by
# sched_switch, as well as a starting timestamp for calculating cpu usage.
#
# Licensed under the Apache License, Version 2.0 (the "License")
# Copyright (C) 2021 Liu Chao.
#
# 07-Jan-2021    Liu Chao       Created this.

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
import argparse
from datetime import datetime

# arguments
examples = """examples:
    ./cpuload                # display tasks when cpu overload
    ./cpuload -t 100000000   # display when non-idle for 100000000 ns
    ./cpuload -n 5           # display top 5 tasks details
    ./cpuload -u 30          # display tasks use more than 30 percent cpu
    ./cpuload -c 3           # only display cpu0 and cpu1
"""
parser = argparse.ArgumentParser(
    description="display tasks when cpu overload",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-t", "--time", default=1000000000,
    help="minimum nsec to print, default 1000000000")
parser.add_argument("-n", "--number", default=3,
    help="maximum tasks to print, default 3")
parser.add_argument("-u", "--usage", default=30,
    help="minimum usage to print, default 30")
parser.add_argument("-c", "--cpumask", default=-1,
    help="target cpus' mask to print, default all cpus")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
time = int(args.time)
number = int(args.number)
usage = int(args.usage)
target = int(args.cpumask)
debug = 0

# define BPF program
bpf_text = """
#include <linux/sched.h>

#define WARN_NSEC """ + str(time) + """
#define MAX_ENTRY 1024

enum state {
    IDLE,
    OVERLOAD,
    OVERFLOW
};

struct cpu_data_t {
    u64 begin_time;
    u64 prev_time;
    int number;
    int state;
};

struct task_data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u64 delta;
};

struct data_t {
    u64 total_time;
    int number;
};

BPF_PERCPU_ARRAY(cpu_data, struct cpu_data_t, 1);

BPF_PERCPU_ARRAY(task_data, struct task_data_t, MAX_ENTRY);

BPF_PERF_OUTPUT(events);
TRACEPOINT_PROBE(sched, sched_switch) {
    u32 zero = 0;
    u64 now = bpf_ktime_get_ns();
    struct data_t data = {};
    struct cpu_data_t *cpu = cpu_data.lookup(&zero);
    struct task_data_t *task;

    if (cpu == 0)
        return 0;

    if (args->prev_pid == 0 || cpu->begin_time == 0) {
        cpu->begin_time = now;
        cpu->prev_time = now;
        cpu->number = 0;
        cpu->state = IDLE;
        return 0;
    }

    if (cpu->state == OVERLOAD || cpu->state == OVERFLOW)
        return 0;

    if (cpu->number >= MAX_ENTRY) {
        data.number = MAX_ENTRY;
        data.total_time = cpu->prev_time - cpu->begin_time;
        cpu->state = OVERFLOW;
        events.perf_submit(args, &data, sizeof(data));
        return 0;
    }

    task = task_data.lookup(&cpu->number);
    if (task == 0)
        return 0;

    task->pid = args->prev_pid;
    __builtin_memcpy(&task->comm, &args->prev_comm, sizeof(task->comm));
    task->delta = now - cpu->prev_time;
    cpu->prev_time = now;
    cpu->number++;

    data.total_time = now - cpu->begin_time;
    if (data.total_time > WARN_NSEC) {
        data.number = cpu->number;
        cpu->state = OVERLOAD;
        events.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}
"""

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text)

print("Tracing task switch. Output when cpu is overload. Ctrl-C to end.")

print("%-19s %-14s %-7s %-4s %-8s %-5s" %
        ("DATE", "COMM", "PID", "CPU", "TIME(ms)", "USAGE"))

# process event
def print_event(cpu, data, size):
    if target & 1 << cpu == 0:
        return 0
    date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    data = b["events"].event(data)
    dic = {}
    for i in range(0, data.number):
        task = b["task_data"][i][cpu]
        entry = dic.get(task.pid)
        if entry is not None:
            entry.delta += task.delta
        else:
            dic[task.pid] = task

    count = 0
    for item in sorted(dic.items(), key=lambda x: x[1].delta, reverse=True):
        if count >= number:
            break
        task = item[1]
        u = task.delta * 100 / data.total_time
        if u < usage:
            break
        print("%s %-14.14s %-7s %-4s %-8.3f %05.2f%%" % (
            date,
            task.comm.decode("utf-8", "replace"),
            task.pid,
            cpu,
            float(task.delta) / 1000000,
            u))
        count += 1
    dic.clear()

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

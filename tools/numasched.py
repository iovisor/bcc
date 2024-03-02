#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# numasched  Trace task NUMA switch
#            For Linux, uses BCC, eBPF.
#
# USAGE: numasched [-p PID] [-t TID] [-c COMM]
#
# This script tracks NUMA migrations of tasks, and in general, frequent
# NUMA migrations can cause poor performance.
#
# Copyright 2022 CESTC, Co.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Dec-2022   Rong Tao    Created this.

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import sleep


# arguments
examples = """examples:
    ./numasched             # trace all processes
    ./numasched -p 185      # trace PID 185 only
"""
parser = argparse.ArgumentParser(
    description="Trace task NUMA switch",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-t", "--tid",
    help="trace this TID only")
parser.add_argument("-c", "--comm",
    help="trace this COMM only")
args = parser.parse_args()


bpf_text = """
#include <linux/sched.h>
#include <linux/topology.h>

struct data_t {
    char comm[TASK_COMM_LEN];
    u32 pid;
    u32 tid;
    u32 old_nid;
    u32 new_nid;
};
BPF_PERF_OUTPUT(events);

struct val_t {
    u32 nid;
};
BPF_HASH(numaid_info, u32, struct val_t);


TRACEPOINT_PROBE(sched, sched_switch)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    u32 new_nid = bpf_get_numa_node_id();
    struct val_t val = {}, *valp;
    u32 old_nid;

    if (FILTER_PID)
        return 0;

    if (FILTER_TID)
        return 0;

    val.nid = new_nid;

    valp = numaid_info.lookup(&tid);
    if (!valp)
        goto update;

    old_nid = valp->nid;

    if (old_nid != new_nid) {
        struct data_t data = {};

        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        data.pid = pid;
        data.tid = tid;
        data.old_nid = old_nid;
        data.new_nid = new_nid;

        events.perf_submit(args, &data, sizeof(data));
    }

update:
    numaid_info.update(&tid, &val);
    return 0;
}
"""

if args.pid:
    bpf_text = bpf_text.replace('FILTER_PID', 'pid != %s' % args.pid)
else:
    # always skip PID=0
    bpf_text = bpf_text.replace('FILTER_PID', 'pid == 0')

if args.tid:
    bpf_text = bpf_text.replace('FILTER_TID', 'tid != %s' % args.tid)
else:
    # always skip TID=0
    bpf_text = bpf_text.replace('FILTER_TID', 'tid == 0')

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)

    # Filter events by comm
    if args.comm:
        if not args.comm == event.comm.decode('utf-8', 'replace'):
            return

    print("%-8s %-8d %-8d %-8d -> %-8d %-8s" %
        (strftime("%H:%M:%S"),
        event.pid,
        event.tid,
        event.old_nid,
        event.new_nid,
        event.comm))


b = BPF(text=bpf_text)

print("Tracing task NUMA switch...")
print("%-8s %-8s %-8s %-8s    %-8s %-8s" %
    ("TIME", "PID", "TID", "SRC_NID", "DST_NID", "COMM"))

b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()


#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# drsnoop  Trace direct reclaim and print details including issuing PID.
#       For Linux, uses BCC, eBPF.
#
# This uses in-kernel eBPF maps to cache process details (PID and comm) by
# direct reclaim begin, as well as a starting timestamp for calculating
# latency.
#
# Copyright (c) 2019 Wenbo Zhang
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 20-Feb-2019   Wenbo Zhang   Created this.
# 09-Mar-2019   Wenbo Zhang   Updated for show sys mem info.

from __future__ import print_function
from bcc import ArgString, BPF
import argparse
from datetime import datetime, timedelta
import os
import math

# symbols
kallsyms = "/proc/kallsyms"

# arguments
examples = """examples:
    ./drsnoop           # trace all direct reclaim
    ./drsnoop -T        # include timestamps
    ./drsnoop -U        # include UID
    ./drsnoop -P 181    # only trace PID 181
    ./drsnoop -t 123    # only trace TID 123
    ./drsnoop -u 1000   # only trace UID 1000
    ./drsnoop -d 10     # trace for 10 seconds only
    ./drsnoop -n main   # only print process names containing "main"
"""
parser = argparse.ArgumentParser(
    description="Trace direct reclaim",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
                    help="include timestamp on output")
parser.add_argument("-U", "--print-uid", action="store_true",
                    help="print UID column")
parser.add_argument("-p", "--pid",
                    help="trace this PID only")
parser.add_argument("-t", "--tid",
                    help="trace this TID only")
parser.add_argument("-u", "--uid",
                    help="trace this UID only")
parser.add_argument("-d", "--duration",
                    help="total duration of trace in seconds")
parser.add_argument("-n", "--name",
                    type=ArgString,
                    help="only print process names containing this name")
parser.add_argument("-v", "--verbose", action="store_true",
                    help="show system memory state")
parser.add_argument("--ebpf", action="store_true",
                    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0
if args.duration:
    args.duration = timedelta(seconds=int(args.duration))


# vm_stat
vm_stat_addr = ''
with open(kallsyms) as syms:
    for line in syms:
        (addr, size, name) = line.rstrip().split(" ", 2)
        name = name.split("\t")[0]
        if name == "vm_stat":
            vm_stat_addr = "0x" + addr
            break
        if name == "vm_zone_stat":
            vm_stat_addr = "0x" + addr
            break
    if vm_stat_addr == '':
        print("ERROR: no vm_stat or vm_zone_stat in /proc/kallsyms. Exiting.")
        print("HINT: the kernel should be built with CONFIG_KALLSYMS_ALL.")
        exit()

NR_FREE_PAGES = 0

PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
PAGE_SHIFT = int(math.log(PAGE_SIZE) / math.log(2))

def K(x):
    return x << (PAGE_SHIFT - 10)

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/mmzone.h>

struct val_t {
    u64 id;
    u64 ts; // start time
    char name[TASK_COMM_LEN];
    u64 vm_stat[NR_VM_ZONE_STAT_ITEMS];
};

struct data_t {
    u64 id;
    u32 uid;
    u64 nr_reclaimed;
    u64 delta;
    u64 ts;    // end time
    char name[TASK_COMM_LEN];
    u64 vm_stat[NR_VM_ZONE_STAT_ITEMS];
};

BPF_HASH(start, u64, struct val_t);
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(vmscan, mm_vmscan_direct_reclaim_begin) {
    struct val_t val = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part
    u32 uid = bpf_get_current_uid_gid();
    u64 ts;

    PID_TID_FILTER
    UID_FILTER
    if (bpf_get_current_comm(&val.name, sizeof(val.name)) == 0) {
        val.id = id;
        val.ts = bpf_ktime_get_ns();
        bpf_probe_read_kernel(&val.vm_stat, sizeof(val.vm_stat), (const void *)%s);
        start.update(&id, &val);
    }
    return 0;
}

TRACEPOINT_PROBE(vmscan, mm_vmscan_direct_reclaim_end) {
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp;
    struct data_t data = {};
    u64 ts = bpf_ktime_get_ns();

    valp = start.lookup(&id);
    if (valp == NULL) {
        // missed entry
        return 0;
    }

    data.delta = ts - valp->ts;
    data.ts = ts / 1000;
    data.id = valp->id;
    data.uid = bpf_get_current_uid_gid();
    bpf_probe_read_kernel(&data.name, sizeof(data.name), valp->name);
    bpf_probe_read_kernel(&data.vm_stat, sizeof(data.vm_stat), valp->vm_stat);
    data.nr_reclaimed = args->nr_reclaimed;

    events.perf_submit(args, &data, sizeof(data));
    start.delete(&id);

    return 0;
}
""" % vm_stat_addr

if args.tid:  # TID trumps PID
    bpf_text = bpf_text.replace('PID_TID_FILTER',
                                'if (tid != %s) { return 0; }' % args.tid)
elif args.pid:
    bpf_text = bpf_text.replace('PID_TID_FILTER',
                                'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('PID_TID_FILTER', '')
if args.uid:
    bpf_text = bpf_text.replace('UID_FILTER',
                                'if (uid != %s) { return 0; }' % args.uid)
else:
    bpf_text = bpf_text.replace('UID_FILTER', '')
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text)

initial_ts = 0

# header
if args.timestamp:
    print("%-14s" % ("TIME(s)"), end="")
if args.print_uid:
    print("%-6s" % ("UID"), end="")
print("%-14s %-6s %8s %5s" %
      ("COMM", "TID" if args.tid else "PID", "LAT(ms)", "PAGES"), end="")
if args.verbose:
    print("%10s" % ("FREE(KB)"))
else:
    print("")

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)

    global initial_ts

    if not initial_ts:
        initial_ts = event.ts

    if args.name and bytes(args.name) not in event.name:
        return

    if args.timestamp:
        delta = event.ts - initial_ts
        print("%-14.9f" % (float(delta) / 1000000), end="")

    if args.print_uid:
        print("%-6d" % event.uid, end="")

    print("%-14.14s %-6s %8.2f %5d" %
          (event.name.decode('utf-8', 'replace'),
           event.id & 0xffffffff if args.tid else event.id >> 32,
           float(event.delta) / 1000000, event.nr_reclaimed), end="")
    if args.verbose:
        print("%10d" % K(event.vm_stat[NR_FREE_PAGES]))
    else:
        print("")


# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
start_time = datetime.now()
while not args.duration or datetime.now() - start_time < args.duration:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

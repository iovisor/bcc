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
# Copyright (c) 2019 Ethercflow
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 20-Feb-2019   Ethercflow   Created this.

from __future__ import print_function
from bcc import ArgString, BPF
import argparse
from datetime import datetime, timedelta

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
parser.add_argument("--ebpf", action="store_true",
                    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0
if args.duration:
    args.duration = timedelta(seconds=int(args.duration))

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct val_t {
    u64 id;
    u64 ts; // start time
    char name[TASK_COMM_LEN];
};

struct data_t {
    u64 id;
    u32 uid;
    u64 nr_reclaimed;
    u64 delta;
    u64 ts;    // end time
    char name[TASK_COMM_LEN];
};

BPF_HASH(start, u64, struct val_t);
BPF_PERF_OUTPUT(events);

int trace_direct_reclaim_begin(void)
{
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
        start.update(&id, &val);
    }
    return 0;
}

struct reclaimed_args {
    // from /sys/kernel/debug/tracing/events/vmscan/mm_vmscan_direct_reclaim_-
    // end/format
    u64 __unused__;
    u64 nr_reclaimed;
};

int trace_direct_reclaim_end(struct reclaimed_args *args)
{
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
    bpf_probe_read(&data.name, sizeof(data.name), valp->name);
    data.nr_reclaimed = args->nr_reclaimed;

    events.perf_submit(args, &data, sizeof(data));
    start.delete(&id);

    return 0;
}
"""
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
b.attach_tracepoint(tp="vmscan:mm_vmscan_direct_reclaim_begin",
                    fn_name="trace_direct_reclaim_begin")
b.attach_tracepoint(tp="vmscan:mm_vmscan_direct_reclaim_end",
                    fn_name="trace_direct_reclaim_end")

initial_ts = 0

# header
if args.timestamp:
    print("%-14s" % ("TIME(s)"), end="")
if args.print_uid:
    print("%-6s" % ("UID"), end="")
print("%-14s %-8s %-14s %7s" %
      ("COMM", "TID" if args.tid else "PID", "LAT(ms)", "PAGES"))

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

    print("%-14.14s %-8s %-14f %7s" %
          (event.name.decode('utf-8', 'replace'),
           event.id & 0xffffffff if args.tid else event.id >> 32,
           float(event.delta) / 1000000, event.nr_reclaimed))


# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
start_time = datetime.now()
while not args.duration or datetime.now() - start_time < args.duration:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

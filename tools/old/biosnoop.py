#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# biosnoop  Trace block device I/O and print details including issuing PID.
#       For Linux, uses BCC, eBPF.
#
# This uses in-kernel eBPF maps to cache process details (PID and comm) by I/O
# request, as well as a starting timestamp for calculating I/O latency.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 16-Sep-2015   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

struct val_t {
    u32 pid;
    char name[TASK_COMM_LEN];
};

BPF_HASH(start, struct request *);
BPF_HASH(infobyreq, struct request *, struct val_t);

// cache PID and comm by-req
int trace_pid_start(struct pt_regs *ctx, struct request *req)
{
    struct val_t val = {};

    if (bpf_get_current_comm(&val.name, sizeof(val.name)) == 0) {
        val.pid = bpf_get_current_pid_tgid();
        infobyreq.update(&req, &val);
    }

    return 0;
}

// time block I/O
int trace_req_start(struct pt_regs *ctx, struct request *req)
{
    u64 ts;

    ts = bpf_ktime_get_ns();
    start.update(&req, &ts);

    return 0;
}

// output
int trace_req_completion(struct pt_regs *ctx, struct request *req)
{
    u64 *tsp, delta;
    u32 *pidp = 0;
    struct val_t *valp;

    // fetch timestamp and calculate delta
    tsp = start.lookup(&req);
    if (tsp == 0) {
        // missed tracing issue
        return 0;
    }
    delta = bpf_ktime_get_ns() - *tsp;

    //
    // Fetch and output issuing pid and comm.
    // As bpf_trace_prink() is limited to a maximum of 1 string and 2
    // integers, we'll use more than one to output the data.
    //
    valp = infobyreq.lookup(&req);
    if (valp == 0) {
        bpf_trace_printk("0 0 ? %d\\n", req->__data_len);
    } else {
        bpf_trace_printk("0 %d %s %d\\n", valp->pid, valp->name,
            req->__data_len);
    }

    // output remaining details
    if (req->cmd_flags & REQ_WRITE) {
        bpf_trace_printk("1 W %s %d %d ?\\n", req->rq_disk->disk_name,
            req->__sector, delta / 1000);
    } else {
        bpf_trace_printk("1 R %s %d %d ?\\n", req->rq_disk->disk_name,
            req->__sector, delta / 1000);
    }

    start.delete(&req);
    infobyreq.delete(&req);

    return 0;
}
""", debug=0)
b.attach_kprobe(event="blk_account_io_start", fn_name="trace_pid_start")
b.attach_kprobe(event="blk_start_request", fn_name="trace_req_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")
b.attach_kprobe(event="blk_account_io_completion",
    fn_name="trace_req_completion")

# header
print("%-14s %-14s %-6s %-7s %-2s %-9s %-7s %7s" % ("TIME(s)", "COMM", "PID",
    "DISK", "T", "SECTOR", "BYTES", "LAT(ms)"))

start_ts = 0

# format output
while 1:
    (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    args = msg.split(" ")

    if start_ts == 0:
        start_ts = ts

    if args[0] == "0":
        (real_pid, real_comm, bytes_s) = (args[1], args[2], args[3])
        continue
    else:
        (type_s, disk_s, sector_s, us_s) = (args[1], args[2], args[3],
            args[4])

    ms = float(int(us_s, 10)) / 1000

    print("%-14.9f %-14.14s %-6s %-7s %-2s %-9s %-7s %7.2f" % (
        ts - start_ts, real_comm, real_pid, disk_s, type_s, sector_s,
        bytes_s, ms))

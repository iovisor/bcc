#!/usr/bin/python
#
# gethostlatency  Show latency for getaddrinfo/gethostbyname[2] calls.
#                 For Linux, uses BCC, eBPF. Embedded C.
#
# This can be useful for identifying DNS latency, by identifying which
# remote host name lookups were slow, and by how much.
#
# This uses dynamic tracing of user-level functions and registers, and may
# need modifications to match your software and processor architecture.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 28-Jan-2016    Brendan Gregg   Created this.
# 30-Mar-2016   Allan McAleavy updated for BPF_PERF_OUTPUT

from __future__ import print_function
from bcc import BPF
from time import strftime
import argparse

examples = """examples:
    ./gethostlatency           # time getaddrinfo/gethostbyname[2] calls
    ./gethostlatency -p 181    # only trace PID 181
"""
parser = argparse.ArgumentParser(
    description="Show latency for getaddrinfo/gethostbyname[2] calls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", help="trace this PID only", type=int,
    default=-1)
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct val_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char host[80];
    u64 ts;
};

struct data_t {
    u32 pid;
    u64 delta;
    char comm[TASK_COMM_LEN];
    char host[80];
};

BPF_HASH(start, u32, struct val_t);
BPF_PERF_OUTPUT(events);

int do_entry(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;

    struct val_t val = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        bpf_probe_read_user(&val.host, sizeof(val.host),
                       (void *)PT_REGS_PARM1(ctx));
        val.pid = pid;
        val.ts = bpf_ktime_get_ns();
        start.update(&tid, &val);
    }

    return 0;
}

int do_return(struct pt_regs *ctx) {
    struct val_t *valp;
    struct data_t data = {};
    u64 delta;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;

    u64 tsp = bpf_ktime_get_ns();

    valp = start.lookup(&tid);
    if (valp == 0)
        return 0;       // missed start

    bpf_probe_read_kernel(&data.comm, sizeof(data.comm), valp->comm);
    bpf_probe_read_kernel(&data.host, sizeof(data.host), (void *)valp->host);
    data.pid = valp->pid;
    data.delta = tsp - valp->ts;
    events.perf_submit(ctx, &data, sizeof(data));
    start.delete(&tid);
    return 0;
}
"""
if args.ebpf:
    print(bpf_text)
    exit()

b = BPF(text=bpf_text)
b.attach_uprobe(name="c", sym="getaddrinfo", fn_name="do_entry", pid=args.pid)
b.attach_uprobe(name="c", sym="gethostbyname", fn_name="do_entry",
                pid=args.pid)
b.attach_uprobe(name="c", sym="gethostbyname2", fn_name="do_entry",
                pid=args.pid)
b.attach_uretprobe(name="c", sym="getaddrinfo", fn_name="do_return",
                   pid=args.pid)
b.attach_uretprobe(name="c", sym="gethostbyname", fn_name="do_return",
                   pid=args.pid)
b.attach_uretprobe(name="c", sym="gethostbyname2", fn_name="do_return",
                   pid=args.pid)

# header
print("%-9s %-7s %-16s %10s %s" % ("TIME", "PID", "COMM", "LATms", "HOST"))

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%-9s %-7d %-16s %10.2f %s" % (strftime("%H:%M:%S"), event.pid,
        event.comm.decode('utf-8', 'replace'), (float(event.delta) / 1000000),
        event.host.decode('utf-8', 'replace')))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

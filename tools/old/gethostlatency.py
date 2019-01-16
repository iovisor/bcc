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

from __future__ import print_function
from bcc import BPF
from time import strftime

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

struct val_t {
    char host[80];
    u64 ts;
};
BPF_HASH(start, u32, struct val_t);

int do_entry(struct pt_regs *ctx) {
    if (!ctx->di)
        return 0;
    struct val_t val = {};
    u32 pid = bpf_get_current_pid_tgid();
    bpf_probe_read(&val.host, sizeof(val.host), (void *)ctx->di);
    val.ts = bpf_ktime_get_ns();
    start.update(&pid, &val);
    return 0;
}

int do_return(struct pt_regs *ctx) {
    struct val_t *valp;
    u64 delta;
    u32 pid = bpf_get_current_pid_tgid();

    valp = start.lookup(&pid);
    if (valp == 0)
        return 0;       // missed start

    delta = (bpf_ktime_get_ns() - valp->ts) / 1000;
    bpf_trace_printk("%d %s\\n", delta, valp->host);
    start.delete(&pid);
    return 0;
}
"""
b = BPF(text=bpf_text)
b.attach_uprobe(name="c", sym="getaddrinfo", fn_name="do_entry")
b.attach_uprobe(name="c", sym="gethostbyname", fn_name="do_entry")
b.attach_uprobe(name="c", sym="gethostbyname2", fn_name="do_entry")
b.attach_uretprobe(name="c", sym="getaddrinfo", fn_name="do_return")
b.attach_uretprobe(name="c", sym="gethostbyname", fn_name="do_return")
b.attach_uretprobe(name="c", sym="gethostbyname2", fn_name="do_return")

# header
print("%-9s %-6s %-12s %6s %s" % ("TIME", "PID", "COMM", "LATms", "HOST"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    (delta, host) = msg.split(" ")
    deltams = int(delta) / 1000
    print("%-9s %-6d %-12.12s %6.2f %s" % (strftime("%H:%M:%S"), pid, task,
        deltams, host))

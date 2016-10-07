#!/usr/bin/python
#
# mysqld_query    Trace MySQL server queries. Example of USDT tracing.
#                 For Linux, uses BCC, BPF. Embedded C.
#
# USAGE: mysqld_query PID
#
# This uses USDT probes, and needs a MySQL server with -DENABLE_DTRACE=1.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF, USDT
import sys

if len(sys.argv) < 2:
    print("USAGE: mysqld_latency PID")
    exit()
pid = sys.argv[1]
debug = 0

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
int do_trace(struct pt_regs *ctx) {
    uint64_t addr;
    char query[128];
    /*
     * Read the first argument from the query-start probe, which is the query.
     * The format of this probe is:
     * query-start(query, connectionid, database, user, host)
     * see: https://dev.mysql.com/doc/refman/5.7/en/dba-dtrace-ref-query.html
     */
    bpf_usdt_readarg(1, ctx, &addr);
    bpf_trace_printk("%s\\n", addr);
    return 0;
};
"""

# enable USDT probe from given PID
u = USDT(pid=int(pid))
u.enable_probe(probe="query__start", fn_name="do_trace")
if debug:
    print(u.get_text())
    print(bpf_text)

# initialize BPF
b = BPF(text=bpf_text, usdt_contexts=[u])

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "QUERY"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        print("value error")
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))

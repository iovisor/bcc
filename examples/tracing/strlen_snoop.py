#!/usr/bin/python
#
# strlen_snoop  Trace strlen() library function for a given PID.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: strlensnoop PID
#
# Try running this on a separate bash shell.
#
# Written as a basic example of BCC and uprobes.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF
from os import getpid
import sys

if len(sys.argv) < 2:
    print("USAGE: strlensnoop PID")
    exit()
pid = sys.argv[1]

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
int printarg(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;

    u32 pid = bpf_get_current_pid_tgid();
    if (pid != PID)
        return 0;

    char str[80] = {};
    bpf_probe_read(&str, sizeof(str), (void *)PT_REGS_PARM1(ctx));
    bpf_trace_printk("%s\\n", &str);

    return 0;
};
"""
bpf_text = bpf_text.replace('PID', pid)
b = BPF(text=bpf_text)
b.attach_uprobe(name="c", sym="strlen", fn_name="printarg")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "STRLEN"))

# format output
me = getpid()
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    if pid == me or msg == "":
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))

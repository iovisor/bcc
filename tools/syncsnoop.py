#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# syncsnoop Trace sync() syscall.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of BCC trace & reformat. See
# examples/hello_world.py for a BCC trace with default output example.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Aug-2015   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF

# load BPF program
b = BPF(text="""
void kprobe__sys_sync(void *ctx) {
    bpf_trace_printk("sync()\\n");
};
""")

# header
print("%-18s %s" % ("TIME(s)", "CALL"))

# format output
while 1:
    (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    print("%-18.9f %s" % (ts, msg))

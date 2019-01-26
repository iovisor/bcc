#!/usr/bin/python
#
# mallocstacks  Trace malloc() calls in a process and print the full
#               stack trace for all callsites.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# This script is a basic example of the new Linux 4.6+ BPF_STACK_TRACE
# table API.
#
# Copyright 2016 GitHub, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF
from time import sleep
import sys

if len(sys.argv) < 2:
    print("USAGE: mallocstacks PID")
    exit()
pid = int(sys.argv[1])

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>

BPF_HASH(calls, int);
BPF_STACK_TRACE(stack_traces, 1024);

int alloc_enter(struct pt_regs *ctx, size_t size) {
    int key = stack_traces.get_stackid(ctx,
        BPF_F_USER_STACK|BPF_F_REUSE_STACKID);
    if (key < 0)
        return 0;

    // could also use `calls.increment(key, size);`
    u64 zero = 0, *val;
    val = calls.lookup_or_init(&key, &zero);
    (*val) += size;
    return 0;
};
""")

b.attach_uprobe(name="c", sym="malloc", fn_name="alloc_enter", pid=pid)
print("Attaching to malloc in pid %d, Ctrl+C to quit." % pid)

# sleep until Ctrl-C
try:
    sleep(99999999)
except KeyboardInterrupt:
    pass

calls = b.get_table("calls")
stack_traces = b.get_table("stack_traces")

for k, v in reversed(sorted(calls.items(), key=lambda c: c[1].value)):
    print("%d bytes allocated at:" % v.value)
    for addr in stack_traces.walk(k.value):
        print("\t%s" % b.sym(addr, pid, show_offset=True))

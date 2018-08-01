#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# vfscount  Count VFS calls ("vfs_*").
#           For Linux, uses BCC, eBPF. See .c file.
#
# Written as a basic example of counting functions.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Aug-2015   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>

struct key_t {
    u64 ip;
};

BPF_HASH(counts, struct key_t, u64, 256);

int do_count(struct pt_regs *ctx) {
    struct key_t key = {};
    key.ip = PT_REGS_IP(ctx);
    counts.increment(key);
    return 0;
}
""")
b.attach_kprobe(event_re="^vfs_.*", fn_name="do_count")

# header
print("Tracing... Ctrl-C to end.")

# output
try:
    sleep(99999999)
except KeyboardInterrupt:
    pass

print("\n%-16s %-26s %8s" % ("ADDR", "FUNC", "COUNT"))
counts = b.get_table("counts")
for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    print("%-16x %-26s %8d" % (k.ip, b.ksym(k.ip), v.value))

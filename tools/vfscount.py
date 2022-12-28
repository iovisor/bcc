#!/usr/bin/env python
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
from sys import argv
import json
import argparse

examples = """examples:
    ./vfscount           # counts VFS calls  during time
    ./vfscount -j        # print output in json format
"""
parser = argparse.ArgumentParser(
    description="Counts VFS calls  during time",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument(
    "duration", nargs="?", default=10, help="Duration, in seconds, to run")
parser.add_argument("-j", "--json", action="store_true",
    help="json output")
args = parser.parse_args()

if int(args.duration) == 0:
    print ("print duration must be non-zero")
    exit()

interval = 99999999
if args.duration:
    interval = int(args.duration)

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
    counts.atomic_increment(key);
    return 0;
}
""")
b.attach_kprobe(event_re="^vfs_.*", fn_name="do_count")

# header
if not args.json:
    print("Tracing... Ctrl-C to end.")

# output
try:
    sleep(interval)
except KeyboardInterrupt:
    pass

if not args.json:
    print("\n%-16s %-26s %8s" % ("ADDR", "FUNC", "COUNT"))
counts = b.get_table("counts")
for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    print("%-16x %-26s %8d" % (k.ip, b.ksym(k.ip), v.value)) if not args.json else \
        print(json.dumps({ "addr": k.ip, "func": b.ksym(k.ip).decode(), "count": v.value}))

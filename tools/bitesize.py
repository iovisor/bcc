#!/usr/bin/env python
#
# bitehist.py   Block I/O size histogram.
#               For Linux, uses BCC, eBPF. See .c file.
#
# USAGE: bitesize
#
# Ctrl-C will print the partially gathered histogram then exit.
#
# Copyright (c) 2016 Allan McAleavy
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 05-Feb-2016 Allan McAleavy ran pep8 against file
# 19-Mar-2019 Brendan Gregg  Switched to use tracepoints.

from bcc import BPF
from time import sleep
import argparse

# arguments
examples = """examples:
    ./bitesize          # block I/O size histogram
    ./bitesize -j       # print json output
"""
parser = argparse.ArgumentParser(
    description="Block I/O size histogram",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-j", "--json", action="store_true",
    help="json output")
parser.add_argument("-d", "--duration", default=99999999,
    help="total duration of trace in seconds")
args = parser.parse_args()
duration = int(args.duration)

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

struct proc_key_t {
    char name[TASK_COMM_LEN];
    u64 slot;
};

BPF_HISTOGRAM(dist, struct proc_key_t);

TRACEPOINT_PROBE(block, block_rq_issue)
{
    struct proc_key_t key = {.slot = bpf_log2l(args->bytes / 1024)};
    bpf_probe_read_kernel(&key.name, sizeof(key.name), args->comm);
    dist.atomic_increment(key);
    return 0;
}
"""

# load BPF program
b = BPF(text=bpf_text)

if not args.json:
    print("Tracing block I/O... Hit Ctrl-C to end.")

# trace until Ctrl-C
dist = b.get_table("dist")

try:
    sleep(duration)
except KeyboardInterrupt:
    pass

if args.json:
    dist.print_json_hist("kbytes", "comm",
        section_print_fn=bytes.decode)
else:
    dist.print_log2_hist("Kbytes", "Process Name",
        section_print_fn=bytes.decode)

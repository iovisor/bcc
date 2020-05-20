#!/usr/bin/python
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
    dist.increment(key);
    return 0;
}
"""

# load BPF program
b = BPF(text=bpf_text)

print("Tracing block I/O... Hit Ctrl-C to end.")

# trace until Ctrl-C
dist = b.get_table("dist")

try:
    sleep(99999999)
except KeyboardInterrupt:
    dist.print_log2_hist("Kbytes", "Process Name",
            section_print_fn=bytes.decode)

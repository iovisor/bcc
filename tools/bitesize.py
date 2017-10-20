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

from bcc import BPF
from time import sleep

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

struct proc_key_t {
    char name[TASK_COMM_LEN];
    u64 slot;
};

struct val_t {
    char name[TASK_COMM_LEN];
};

BPF_HISTOGRAM(dist, struct proc_key_t);
BPF_HASH(commbyreq, struct request *, struct val_t);

int trace_pid_start(struct pt_regs *ctx, struct request *req)
{
    struct val_t val = {};

    if (bpf_get_current_comm(&val.name, sizeof(val.name)) == 0) {
        commbyreq.update(&req, &val);
    }
    return 0;
}

int do_count(struct pt_regs *ctx, struct request *req)
{
    struct val_t *valp;

    valp = commbyreq.lookup(&req);
    if (valp == 0) {
       return 0;
    }

    if (req->__data_len > 0) {
        struct proc_key_t key = {.slot = bpf_log2l(req->__data_len / 1024)};
        bpf_probe_read(&key.name, sizeof(key.name),valp->name);
        dist.increment(key);
    }
    return 0;
}
"""

# load BPF program
b = BPF(text=bpf_text)
b.attach_kprobe(event="blk_account_io_start", fn_name="trace_pid_start")
b.attach_kprobe(event="blk_account_io_completion", fn_name="do_count")

print("Tracing... Hit Ctrl-C to end.")

# trace until Ctrl-C
dist = b.get_table("dist")

try:
    sleep(99999999)
except KeyboardInterrupt:
    dist.print_log2_hist("Kbytes", "Process Name",
            section_print_fn=bytes.decode)

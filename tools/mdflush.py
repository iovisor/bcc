#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# mdflush  Trace md flush events.
#          For Linux, uses BCC, eBPF.
#
# Todo: add more details of the flush (latency, I/O count).
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Feb-2015   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from time import strftime

# define BPF program
bpf_text="""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/blkdev.h>
#include <linux/bio.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char disk[DISK_NAME_LEN];
};
BPF_PERF_OUTPUT(events);

int kprobe__md_flush_request(struct pt_regs *ctx, void *mddev, struct bio *bio)
{
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
/*
 * The following deals with kernel version changes (in mainline 4.14 and 5.12, although
 * it may be backported to earlier kernels) with how the disk name is accessed.
 * We handle both pre- and post-change versions here. Please avoid kernel
 * version tests like this as much as possible: they inflate the code, test,
 * and maintenance burden.
 */
#ifdef bio_dev
    struct gendisk *bi_disk = bio->__BI_DISK__;
#else
    struct gendisk *bi_disk = bio->bi_bdev->bd_disk;
#endif
    bpf_probe_read_kernel(&data.disk, sizeof(data.disk), bi_disk->disk_name);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

if BPF.kernel_struct_has_field('bio', 'bi_bdev') == 1:
    bpf_text = bpf_text.replace('__BI_DISK__', 'bi_bdev->bd_disk')
else:
    bpf_text = bpf_text.replace('__BI_DISK__', 'bi_disk')

# initialize BPF
b = BPF(text=bpf_text)

# header
print("Tracing md flush requests... Hit Ctrl-C to end.")
print("%-8s %-7s %-16s %s" % ("TIME", "PID", "COMM", "DEVICE"))

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%-8s %-7d %-16s %s" % (strftime("%H:%M:%S"), event.pid,
        event.comm.decode('utf-8', 'replace'),
        event.disk.decode('utf-8', 'replace')))

# read events
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

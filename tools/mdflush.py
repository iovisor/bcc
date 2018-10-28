#!/usr/bin/python
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
import ctypes as ct

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/genhd.h>
#include <linux/bio.h>

struct data_t {
    u64 pid;
    char comm[TASK_COMM_LEN];
    char disk[DISK_NAME_LEN];
};
BPF_PERF_OUTPUT(events);

int kprobe__md_flush_request(struct pt_regs *ctx, void *mddev, struct bio *bio)
{
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid();
    data.pid = pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
/*
 * The following deals with a kernel version change (in mainline 4.14, although
 * it may be backported to earlier kernels) with how the disk name is accessed.
 * We handle both pre- and post-change versions here. Please avoid kernel
 * version tests like this as much as possible: they inflate the code, test,
 * and maintenance burden.
 */
#ifdef bio_dev
    struct gendisk *bi_disk = bio->bi_disk;
#else
    struct gendisk *bi_disk = bio->bi_bdev->bd_disk;
#endif
    bpf_probe_read(&data.disk, sizeof(data.disk), bi_disk->disk_name);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
""")

# event data
TASK_COMM_LEN = 16  # linux/sched.h
DISK_NAME_LEN = 32  # linux/genhd.h
class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulonglong),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("disk", ct.c_char * DISK_NAME_LEN)
    ]

# header
print("Tracing md flush requests... Hit Ctrl-C to end.")
print("%-8s %-6s %-16s %s" % ("TIME", "PID", "COMM", "DEVICE"))

# process event
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print("%-8s %-6d %-16s %s" % (strftime("%H:%M:%S"), event.pid,
        event.comm.decode('utf-8', 'replace'),
        event.disk.decode('utf-8', 'replace')))

# read events
b["events"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()

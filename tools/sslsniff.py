#!/usr/bin/python
#
# sslsniff  Captures data on SSL_READ or SSL_WRITE functions of OpenSSL
#           For Linux, uses BCC, eBPF.
#
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 12-Aug-2016    Adrian Lopez   Created this.
# 13-Aug-2016    Mark Drayton   Fix SSL_Read

from __future__ import print_function
import ctypes as ct
from bcc import BPF

prog = """
#include <linux/ptrace.h>
#include <linux/sched.h>        /* For TASK_COMM_LEN */

struct probe_SSL_data_t {
        u64 timestamp_ns;
        u32 pid;
        char comm[TASK_COMM_LEN];
        char v0[472];
        u32 len;
};

BPF_PERF_OUTPUT(perf_SSL_write);

int probe_SSL_write(struct pt_regs *ctx, void *ssl, void *buf, int num) {
        struct probe_SSL_data_t __data = {0};
        __data.timestamp_ns = bpf_ktime_get_ns();
        __data.pid = bpf_get_current_pid_tgid();
        __data.len = num;

        bpf_get_current_comm(&__data.comm, sizeof(__data.comm));

        if ( buf != 0) {
                bpf_probe_read(&__data.v0, sizeof(__data.v0), buf);
        }

        perf_SSL_write.perf_submit(ctx, &__data, sizeof(__data));
        return 0;
}

BPF_PERF_OUTPUT(perf_SSL_read);

BPF_HASH(bufs, u32, u64);

int probe_SSL_read_enter(struct pt_regs *ctx, void *ssl, void *buf, int num) {
        u32 pid = bpf_get_current_pid_tgid();
        bufs.update(&pid, (u64*)&buf);
        return 0;
}

int probe_SSL_read_exit(struct pt_regs *ctx, void *ssl, void *buf, int num) {
        u32 pid = bpf_get_current_pid_tgid();
        u64 *bufp = bufs.lookup(&pid);
        if (bufp == 0) {
                return 0;
        }

        struct probe_SSL_data_t __data = {0};
        __data.timestamp_ns = bpf_ktime_get_ns();
        __data.pid = pid;
        __data.len = PT_REGS_RC(ctx);

        bpf_get_current_comm(&__data.comm, sizeof(__data.comm));

        if (bufp != 0) {
                bpf_probe_read(&__data.v0, sizeof(__data.v0), (char *)*bufp);
        }

        bufs.delete(&pid);

        perf_SSL_read.perf_submit(ctx, &__data, sizeof(__data));
        return 0;
}
"""

b = BPF(text=prog)

# Join to ssl_write
b.attach_uprobe(name="ssl", sym="SSL_write", fn_name="probe_SSL_write")

# Join to ssl_read
# It looks like SSL_read's arguments aren't available in a return probe so you
# need to stash the buffer address in a map on the function entry and read it
# on its exit (Mark Drayton)
b.attach_uprobe(name="ssl", sym="SSL_read", fn_name="probe_SSL_read_enter")
b.attach_uretprobe(name="ssl", sym="SSL_read", fn_name="probe_SSL_read_exit")

# define output data structure in Python
TASK_COMM_LEN = 16  # linux/sched.h
MAX_BUF_SIZE = 472  # Limited by the BPF stack


# Max size of the whole struct: 512 bytes
class Data(ct.Structure):
    _fields_ = [
            ("timestamp_ns", ct.c_ulonglong),
            ("pid", ct.c_uint),
            ("comm", ct.c_char * TASK_COMM_LEN),
            ("v0", ct.c_char * MAX_BUF_SIZE),
            ("len", ct.c_uint)
    ]


# header
print("%-12s %-18s %-16s %-6s %-6s" % ("FUNC", "TIME(s)", "COMM", "PID",
                                       "LEN"))

# process event
start = 0


def print_event_write(cpu, data, size):
    print_event(cpu, data, size, "SSL_WRITE")


def print_event_read(cpu, data, size):
    print_event(cpu, data, size, "SSL_READ")


def print_event(cpu, data, size, rw):
    global start
    event = ct.cast(data, ct.POINTER(Data)).contents
    if start == 0:
        start = event.timestamp_ns
    time_s = (float(event.timestamp_ns - start)) / 1000000000

    s_mark = "-" * 5 + " DATA " + "-" * 5

    e_mark = "-" * 5 + " END DATA " + "-" * 5

    truncated_bytes = event.len - MAX_BUF_SIZE
    if truncated_bytes > 0 :
        e_mark = "-" * 5 + " END DATA (TRUNCATED, " + str(truncated_bytes) + \
                " bytes lost) " + "-" * 5

    print("%-12s %-18.9f %-16s %-6d %-6d\n%s\n%s\n%s\n" % (rw, time_s,
                                                           event.comm,
                                                           event.pid,
                                                           event.len,
                                                           s_mark, event.v0,
                                                           e_mark))

b["perf_SSL_write"].open_perf_buffer(print_event_write)
b["perf_SSL_read"].open_perf_buffer(print_event_read)
while 1:
    b.kprobe_poll()

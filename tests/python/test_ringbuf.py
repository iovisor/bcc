#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import os
import distutils.version
import ctypes as ct
import random
import time
import subprocess
from unittest import main, TestCase, skipUnless

def kernel_version_ge(major, minor):
    # True if running kernel is >= X.Y
    version = distutils.version.LooseVersion(os.uname()[2]).version
    if version[0] > major:
        return True
    if version[0] < major:
        return False
    if minor and version[1] < minor:
        return False
    return True

class TestRingbuf(TestCase):
    @skipUnless(kernel_version_ge(5,8), "requires kernel >= 5.8")
    def test_ringbuf_output(self):
        self.counter = 0

        class Data(ct.Structure):
            _fields_ = [("ts", ct.c_ulonglong)]

        def cb(ctx, data, size):
            self.assertEqual(size, ct.sizeof(Data))
            event = ct.cast(data, ct.POINTER(Data)).contents
            self.counter += 1

        text = """
BPF_RINGBUF_OUTPUT(events, 8);
struct data_t {
    u64 ts;
};
int do_sys_nanosleep(void *ctx) {
    struct data_t data = {bpf_ktime_get_ns()};
    events.ringbuf_output(&data, sizeof(data), 0);
    return 0;
}
"""
        b = BPF(text=text)
        b.attach_kprobe(event=b.get_syscall_fnname("nanosleep"),
                        fn_name="do_sys_nanosleep")
        b.attach_kprobe(event=b.get_syscall_fnname("clock_nanosleep"),
                        fn_name="do_sys_nanosleep")
        b["events"].open_ring_buffer(cb)
        subprocess.call(['sleep', '0.1'])
        b.ring_buffer_poll()
        self.assertGreater(self.counter, 0)
        b.cleanup()

    @skipUnless(kernel_version_ge(5,8), "requires kernel >= 5.8")
    def test_ringbuf_consume(self):
        self.counter = 0

        class Data(ct.Structure):
            _fields_ = [("ts", ct.c_ulonglong)]

        def cb(ctx, data, size):
            self.assertEqual(size, ct.sizeof(Data))
            event = ct.cast(data, ct.POINTER(Data)).contents
            self.counter += 1

        text = """
BPF_RINGBUF_OUTPUT(events, 8);
struct data_t {
    u64 ts;
};
int do_sys_nanosleep(void *ctx) {
    struct data_t data = {bpf_ktime_get_ns()};
    events.ringbuf_output(&data, sizeof(data), 0);
    return 0;
}
"""
        b = BPF(text=text)
        b.attach_kprobe(event=b.get_syscall_fnname("nanosleep"),
                        fn_name="do_sys_nanosleep")
        b.attach_kprobe(event=b.get_syscall_fnname("clock_nanosleep"),
                        fn_name="do_sys_nanosleep")
        b["events"].open_ring_buffer(cb)
        subprocess.call(['sleep', '0.1'])
        b.ring_buffer_consume()
        self.assertGreater(self.counter, 0)
        b.cleanup()

    @skipUnless(kernel_version_ge(5,8), "requires kernel >= 5.8")
    def test_ringbuf_submit(self):
        self.counter = 0

        class Data(ct.Structure):
            _fields_ = [("ts", ct.c_ulonglong)]

        def cb(ctx, data, size):
            self.assertEqual(size, ct.sizeof(Data))
            event = ct.cast(data, ct.POINTER(Data)).contents
            self.counter += 1

        text = """
BPF_RINGBUF_OUTPUT(events, 8);
struct data_t {
    u64 ts;
};
int do_sys_nanosleep(void *ctx) {
    struct data_t *data = events.ringbuf_reserve(sizeof(struct data_t));
    if (!data)
        return 1;
    data->ts = bpf_ktime_get_ns();
    events.ringbuf_submit(data, 0);
    return 0;
}
"""
        b = BPF(text=text)
        b.attach_kprobe(event=b.get_syscall_fnname("nanosleep"),
                        fn_name="do_sys_nanosleep")
        b.attach_kprobe(event=b.get_syscall_fnname("clock_nanosleep"),
                        fn_name="do_sys_nanosleep")
        b["events"].open_ring_buffer(cb)
        subprocess.call(['sleep', '0.1'])
        b.ring_buffer_poll()
        self.assertGreater(self.counter, 0)
        b.cleanup()

    @skipUnless(kernel_version_ge(5,8), "requires kernel >= 5.8")
    def test_ringbuf_discard(self):
        self.counter = 0

        class Data(ct.Structure):
            _fields_ = [("ts", ct.c_ulonglong)]

        def cb(ctx, data, size):
            self.assertEqual(size, ct.sizeof(Data))
            event = ct.cast(data, ct.POINTER(Data)).contents
            self.counter += 1

        text = """
BPF_RINGBUF_OUTPUT(events, 8);
struct data_t {
    u64 ts;
};
int do_sys_nanosleep(void *ctx) {
    struct data_t *data = events.ringbuf_reserve(sizeof(struct data_t));
    if (!data)
        return 1;
    data->ts = bpf_ktime_get_ns();
    events.ringbuf_discard(data, 0);
    return 0;
}
"""
        b = BPF(text=text)
        b.attach_kprobe(event=b.get_syscall_fnname("nanosleep"),
                        fn_name="do_sys_nanosleep")
        b.attach_kprobe(event=b.get_syscall_fnname("clock_nanosleep"),
                        fn_name="do_sys_nanosleep")
        b["events"].open_ring_buffer(cb)
        subprocess.call(['sleep', '0.1'])
        b.ring_buffer_poll()
        self.assertEqual(self.counter, 0)
        b.cleanup()

if __name__ == "__main__":
    main()

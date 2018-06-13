#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import ctypes as ct
import random
import time
import subprocess
from bcc.utils import get_online_cpus
from unittest import main, TestCase

class TestArray(TestCase):
    def test_simple(self):
        b = BPF(text="""BPF_ARRAY(table1, u64, 128);""")
        t1 = b["table1"]
        t1[ct.c_int(0)] = ct.c_ulonglong(100)
        t1[ct.c_int(127)] = ct.c_ulonglong(1000)
        for i, v in t1.items():
            if i.value == 0:
                self.assertEqual(v.value, 100)
            if i.value == 127:
                self.assertEqual(v.value, 1000)
        self.assertEqual(len(t1), 128)

    def test_native_type(self):
        b = BPF(text="""BPF_ARRAY(table1, u64, 128);""")
        t1 = b["table1"]
        t1[0] = ct.c_ulonglong(100)
        t1[-2] = ct.c_ulonglong(37)
        t1[127] = ct.c_ulonglong(1000)
        for i, v in t1.items():
            if i.value == 0:
                self.assertEqual(v.value, 100)
            if i.value == 127:
                self.assertEqual(v.value, 1000)
        self.assertEqual(len(t1), 128)
        self.assertEqual(t1[-2].value, 37)
        self.assertEqual(t1[-1].value, t1[127].value)

    def test_perf_buffer(self):
        self.counter = 0

        class Data(ct.Structure):
            _fields_ = [("ts", ct.c_ulonglong)]

        def cb(cpu, data, size):
            self.assertGreater(size, ct.sizeof(Data))
            event = ct.cast(data, ct.POINTER(Data)).contents
            self.counter += 1

        def lost_cb(lost):
            self.assertGreater(lost, 0)

        text = """
BPF_PERF_OUTPUT(events);
int do_sys_nanosleep(void *ctx) {
    struct {
        u64 ts;
    } data = {bpf_ktime_get_ns()};
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""
        b = BPF(text=text)
        b.attach_kprobe(event=b.get_syscall_fnname("nanosleep"),
                        fn_name="do_sys_nanosleep")
        b["events"].open_perf_buffer(cb, lost_cb=lost_cb)
        subprocess.call(['sleep', '0.1'])
        b.perf_buffer_poll()
        self.assertGreater(self.counter, 0)
        b.cleanup()

    def test_perf_buffer_for_each_cpu(self):
        self.events = []

        class Data(ct.Structure):
            _fields_ = [("cpu", ct.c_ulonglong)]

        def cb(cpu, data, size):
            self.assertGreater(size, ct.sizeof(Data))
            event = ct.cast(data, ct.POINTER(Data)).contents
            self.events.append(event)

        def lost_cb(lost):
            self.assertGreater(lost, 0)

        text = """
BPF_PERF_OUTPUT(events);
int do_sys_nanosleep(void *ctx) {
    struct {
        u64 cpu;
    } data = {bpf_get_smp_processor_id()};
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""
        b = BPF(text=text)
        b.attach_kprobe(event=b.get_syscall_fnname("nanosleep"),
                        fn_name="do_sys_nanosleep")
        b["events"].open_perf_buffer(cb, lost_cb=lost_cb)
        online_cpus = get_online_cpus()
        for cpu in online_cpus:
            subprocess.call(['taskset', '-c', str(cpu), 'sleep', '0.1'])
        b.perf_buffer_poll()
        b.cleanup()
        self.assertGreaterEqual(len(self.events), len(online_cpus), 'Received only {}/{} events'.format(len(self.events), len(online_cpus)))

if __name__ == "__main__":
    main()

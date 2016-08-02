#!/usr/bin/env python
# Copyright (c) 2016 PLUMgrid
# Licensed under the Apache License, Version 2.0 (the "License")

import bcc
import ctypes
import multiprocessing
import os
import time
import unittest

class TestPerfCounter(unittest.TestCase):
    def test_cycles(self):
        text = """
BPF_PERF_ARRAY(cnt1, NUM_CPUS);
BPF_TABLE("array", u32, u64, prev, NUM_CPUS);
BPF_HISTOGRAM(dist);
int kprobe__sys_getuid(void *ctx) {
    u32 cpu = bpf_get_smp_processor_id();
    u64 val = cnt1.perf_read(cpu);
    prev.update(&cpu, &val);
    return 0;
}
int kretprobe__sys_getuid(void *ctx) {
    u32 cpu = bpf_get_smp_processor_id();
    u64 val = cnt1.perf_read(cpu);
    u64 *prevp = prev.lookup(&cpu);
    if (prevp)
        dist.increment(bpf_log2l(val - *prevp));
    return 0;
}
"""
        b = bcc.BPF(text=text, debug=0,
                cflags=["-DNUM_CPUS=%d" % multiprocessing.cpu_count()])
        cnt1 = b["cnt1"]
        try:
            cnt1.open_perf_event(cnt1.HW_CPU_CYCLES)
        except:
            if ctypes.get_errno() == 2:
                raise self.skipTest("hardware events unsupported")
            raise
        for i in range(0, 100):
            os.getuid()
        b["dist"].print_log2_hist()

if __name__ == "__main__":
    unittest.main()

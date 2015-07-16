#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from ctypes import c_uint, c_ulong, Structure
from bpf import BPF
from time import sleep
import sys
from unittest import main, TestCase

text = """
#include <linux/ptrace.h>
BPF_TABLE("hash", u64, u64, stats, 1024);

int count_sched(struct pt_regs *ctx) {
  (*stats.lookup_or_init(ctx->bx, 0))++;
  return 0;
}
"""

class TestTracingEvent(TestCase):
    def setUp(self):
        b = BPF(text=text, debug=0)
        fn = b.load_func("count_sched", BPF.KPROBE)
        self.stats = b.get_table("stats")
        BPF.attach_kprobe(fn, "schedule+50", 0, -1)

    def test_sched1(self):
        for i in range(0, 100):
            sleep(0.01)
        for key, leaf in self.stats.items():
            print("ptr %x:" % key.value, "stat1 %x" % leaf.value)

if __name__ == "__main__":
    main()

#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from ctypes import c_uint, c_ulong, Structure
from bcc import BPF
from time import sleep
import sys
from unittest import main, TestCase

text = """
#include <linux/ptrace.h>
struct Ptr { u64 ptr; };
struct Counters { u64 stat1; };
BPF_TABLE("hash", struct Ptr, struct Counters, stats, 1024);

int count_sched(struct pt_regs *ctx) {
  struct Ptr key = {.ptr=PT_REGS_PARM1(ctx)};
  struct Counters zleaf = {0};
  stats.lookup_or_init(&key, &zleaf)->stat1++;
  return 0;
}
"""

class TestTracingEvent(TestCase):
    def setUp(self):
        b = BPF(text=text, debug=0)
        self.stats = b.get_table("stats")
        b.attach_kprobe(event="finish_task_switch", fn_name="count_sched", pid=0, cpu=-1)

    def test_sched1(self):
        for i in range(0, 100):
            sleep(0.01)
        for key, leaf in self.stats.items():
            print("ptr %x:" % key.ptr, "stat1 %d" % leaf.stat1)

if __name__ == "__main__":
    main()

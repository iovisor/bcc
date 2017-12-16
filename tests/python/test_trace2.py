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
struct Counters { char unused; __int128 stat1; };
BPF_HASH(stats, struct Ptr, struct Counters, 1024);

int count_sched(struct pt_regs *ctx) {
  struct Ptr key = {.ptr=PT_REGS_PARM1(ctx)};
  struct Counters zleaf;

  memset(&zleaf, 0, sizeof(zleaf));
  stats.lookup_or_init(&key, &zleaf)->stat1++;
  return 0;
}
"""

class TestTracingEvent(TestCase):
    def setUp(self):
        b = BPF(text=text, debug=0)
        self.stats = b.get_table("stats")
        b.attach_kprobe(event="finish_task_switch", fn_name="count_sched")

    def test_sched1(self):
        for i in range(0, 100):
            sleep(0.01)
        for key, leaf in self.stats.items():
            print("ptr %x:" % key.ptr, "stat1 (%d %d)" % (leaf.stat1[1], leaf.stat1[0]))

if __name__ == "__main__":
    main()

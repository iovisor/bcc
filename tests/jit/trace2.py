#!/usr/bin/env python

from ctypes import c_uint, c_ulong, Structure
from bpf import BPF
from time import sleep
import sys
from unittest import main, TestCase

text = """
#include <linux/ptrace.h>
#include "../../src/cc/bpf_helpers.h"
struct Ptr { u64 ptr; };
struct Counters { u64 stat1; };
BPF_TABLE("hash", struct Ptr, struct Counters, stats, 1024);

BPF_EXPORT(count_sched)
int count_sched(struct pt_regs *ctx) {
  struct Ptr key = {.ptr=ctx->bx};
  stats.data[(u64)&key].stat1++;
  return 0;
}
"""

class Ptr(Structure):
    _fields_ = [("ptr", c_ulong)]
class Counters(Structure):
    _fields_ = [("stat1", c_ulong)]

class TestTracingEvent(TestCase):
    def setUp(self):
        b = BPF(text=text, debug=0)
        fn = b.load_func("count_sched", BPF.KPROBE)
        self.stats = b.get_table("stats", Ptr, Counters)
        BPF.attach_kprobe(fn, "schedule+50", 0, -1)

    def test_sched1(self):
        for i in range(0, 100):
            sleep(0.01)
        for key in self.stats.iter():
            leaf = self.stats.get(key)
            print("ptr %x:" % key.ptr, "stat1 %x" % leaf.stat1)

if __name__ == "__main__":
    main()

#!/usr/bin/env python

from ctypes import c_uint, c_ulong, Structure
from bpf import BPF
from time import sleep
import sys
from unittest import main, TestCase

arg1 = sys.argv.pop(1)
arg2 = ""
if len(sys.argv) > 1:
  arg2 = sys.argv.pop(1)

class Ptr(Structure):
    _fields_ = [("ptr", c_ulong)]
class Counters(Structure):
    _fields_ = [("stat1", c_ulong)]

class TestTracingEvent(TestCase):
    def setUp(self):
        self.prog = BPF("trace2", arg1, arg2,
                prog_type=BPF.BPF_PROG_TYPE_KPROBE, debug=0)
        self.prog.load("count_sched")
        self.stats = self.prog.table("stats", Ptr, Counters)
        self.prog.attach_kprobe("schedule+50", "count_sched", 0, -1)

    def test_sched1(self):
        for i in range(0, 100):
            sleep(0.01)
        for key in self.stats.iter():
            leaf = self.stats.get(key)
            print("ptr %x:" % key.ptr, "stat1 %x" % leaf.stat1)

if __name__ == "__main__":
    main()

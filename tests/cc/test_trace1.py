#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from ctypes import c_uint, c_ulong, Structure
from bpf import BPF
import os
from time import sleep
import sys
from unittest import main, TestCase

arg1 = sys.argv.pop(1)
arg2 = ""
if len(sys.argv) > 1:
  arg2 = sys.argv.pop(1)

Key = None
Leaf = None
if arg1.endswith(".b"):
    class Key(Structure):
        _fields_ = [("fd", c_ulong)]
    class Leaf(Structure):
        _fields_ = [("stat1", c_ulong),
                    ("stat2", c_ulong)]

class TestKprobe(TestCase):
    def setUp(self):
        b = BPF(arg1, arg2, debug=0)
        fn1 = b.load_func("sys_wr", BPF.KPROBE)
        fn2 = b.load_func("sys_rd", BPF.KPROBE)
        fn3 = b.load_func("sys_bpf", BPF.KPROBE)
        self.stats = b.get_table("stats", Key, Leaf)
        BPF.attach_kprobe(fn1, "sys_write", 0, -1)
        BPF.attach_kprobe(fn2, "sys_read", 0, -1)
        BPF.attach_kprobe(fn2, "htab_map_get_next_key", 0, -1)

    def test_trace1(self):
        with open("/dev/null", "a") as f:
            for i in range(0, 100):
                os.write(f.fileno(), b"")
        with open("/etc/services", "r") as f:
            for i in range(0, 200):
                os.read(f.fileno(), 1)
        for key, leaf in self.stats.items():
            print("fd %x:" % key.fd, "stat1 %d" % leaf.stat1, "stat2 %d" % leaf.stat2)

if __name__ == "__main__":
    main()

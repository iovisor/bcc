#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from ctypes import c_uint, c_ulong, Structure
from bcc import BPF
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
        self.stats = b.get_table("stats", Key, Leaf)
        b.attach_kprobe(event=b.get_syscall_fnname("write"), fn_name="sys_wr")
        b.attach_kprobe(event=b.get_syscall_fnname("read"), fn_name="sys_rd")
        b.attach_kprobe(event="htab_map_get_next_key", fn_name="sys_rd")

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

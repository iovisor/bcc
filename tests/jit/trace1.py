#!/usr/bin/env python

from ctypes import c_uint, c_ulong, Structure
from bpf import BPF
import os
from time import sleep
from unittest import main, TestCase

class Key(Structure):
    _fields_ = [("fd", c_ulong)]
class Leaf(Structure):
    _fields_ = [("stat1", c_ulong),
                ("stat2", c_ulong)]

class TestKprobe(TestCase):
    def setUp(self):
        self.prog = BPF("trace1", "trace1.b", "kprobe.b",
                prog_type=BPF.BPF_PROG_TYPE_KPROBE, debug=0)
        self.prog.load("sys_wr")
        self.prog.load("sys_rd")
        self.prog.load("sys_bpf")
        self.stats = self.prog.table("stats", Key, Leaf)
        self.prog.attach_kprobe("sys_write", "sys_wr", 0, -1)
        self.prog.attach_kprobe("sys_read", "sys_rd", 0, -1)
        self.prog.attach_kprobe("htab_map_get_next_key", "sys_bpf", 0, -1)

    def test_trace1(self):
        with open("/dev/null", "a") as f:
            for i in range(0, 100):
                os.write(f.fileno(), b"")
        with open("/etc/services", "r") as f:
            for i in range(0, 200):
                os.read(f.fileno(), 1)
        for key in self.stats.iter():
            leaf = self.stats.get(key)
            print("fd %x:" % key.fd, "stat1 %d" % leaf.stat1, "stat2 %d" % leaf.stat2)

if __name__ == "__main__":
    main()

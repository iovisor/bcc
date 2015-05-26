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


class TestBlkRequest(TestCase):
    def setUp(self):
        self.prog = BPF("trace3", arg1, arg2,
                prog_type=BPF.BPF_PROG_TYPE_KPROBE, debug=0)
        self.prog.load("probe_blk_start_request")
        self.prog.load("probe_blk_update_request")
        self.latency = self.prog.table("latency", c_uint, c_ulong)
        self.prog.attach_kprobe("blk_start_request", "probe_blk_start_request", 0, -1)
        self.prog.attach_kprobe("blk_update_request", "probe_blk_update_request", 0, -1)

    def test_blk1(self):
        import subprocess
        import os
        for i in range(0, 2):
            with open("/srv/trace3.txt", "w") as f:
                f.write("a" * 4096 * 4096)
            subprocess.call(["sync"])
        os.unlink("/srv/trace3.txt")
        for key in self.latency.iter():
            leaf = self.latency.get(key)
            print("latency %u:" % key.value, "count %u" % leaf.value)
        sys.stdout.flush()

if __name__ == "__main__":
    main()

#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

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
        b = BPF(arg1, arg2, debug=0)
        fn1 = b.load_func("probe_blk_start_request", BPF.KPROBE)
        fn2 = b.load_func("probe_blk_update_request", BPF.KPROBE)
        self.latency = b.get_table("latency", c_uint, c_ulong)
        BPF.attach_kprobe(fn1, "blk_start_request", -1, 0)
        BPF.attach_kprobe(fn2, "blk_update_request", -1, 0)

    def test_blk1(self):
        import subprocess
        import os
        # use /opt instead of /tmp so that it hits a real disk
        for i in range(0, 2):
            subprocess.call(["dd", "if=/dev/zero", "of=/opt/trace3.txt",
                             "count=1024", "bs=4096"])
            subprocess.call(["sync"])
        os.unlink("/opt/trace3.txt")
        for key, leaf in self.latency.items():
            print("latency %u:" % key.value, "count %u" % leaf.value)
        sys.stdout.flush()

if __name__ == "__main__":
    main()

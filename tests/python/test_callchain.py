#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import time
from unittest import main, TestCase

class TestCallchain(TestCase):
    def test_callchain1(self):
        hist = {}
        def cb(pid, callchain):
            counter = hist.get(callchain, 0)
            counter += 1
            hist[callchain] = counter

        b = BPF(text="""
#include <linux/ptrace.h>
int kprobe__finish_task_switch(struct pt_regs *ctx) {
    return 1;
}
""", cb=cb)
        start = time.time()
        while time.time() < start + 1:
            b.kprobe_poll()

        for k, v in hist.items():
            syms = [b.ksym(addr) for addr in k]
            print("%-08d:" % v, syms)

if __name__ == "__main__":
    main()

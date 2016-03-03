#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

import bcc
import ctypes
import os
import unittest

class TestUprobes(unittest.TestCase):
    def test_simple_library(self):
        text = """
#include <uapi/linux/ptrace.h>
BPF_TABLE("array", int, u64, stats, 1);
static void incr(int idx) {
    u64 *ptr = stats.lookup(&idx);
    if (ptr)
        ++(*ptr);
}
int count(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    if (pid == PID)
        incr(0);
    return 0;
}"""
        text = text.replace("PID", "%d" % os.getpid())
        b = bcc.BPF(text=text)
        b.attach_uprobe(name="c", sym="malloc_stats", fn_name="count")
        b.attach_uretprobe(name="c", sym="malloc_stats", fn_name="count")
        libc = ctypes.CDLL("libc.so.6")
        libc.malloc_stats.restype = None
        libc.malloc_stats.argtypes = []
        libc.malloc_stats()
        self.assertEqual(b["stats"][ctypes.c_int(0)].value, 2)
        b.detach_uretprobe(name="c", sym="malloc_stats")
        b.detach_uprobe(name="c", sym="malloc_stats")

    def test_simple_binary(self):
        text = """
#include <uapi/linux/ptrace.h>
BPF_TABLE("array", int, u64, stats, 1);
static void incr(int idx) {
    u64 *ptr = stats.lookup(&idx);
    if (ptr)
        ++(*ptr);
}
int count(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    incr(0);
    return 0;
}"""
        b = bcc.BPF(text=text)
        b.attach_uprobe(name="/usr/bin/python", sym="main", fn_name="count")
        b.attach_uretprobe(name="/usr/bin/python", sym="main", fn_name="count")
        with os.popen("/usr/bin/python -V") as f:
            pass
        self.assertGreater(b["stats"][ctypes.c_int(0)].value, 0)
        b.detach_uretprobe(name="/usr/bin/python", sym="main")
        b.detach_uprobe(name="/usr/bin/python", sym="main")

if __name__ == "__main__":
    unittest.main()

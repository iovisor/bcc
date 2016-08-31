#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

import bcc
import ctypes
import unittest

class TestPassProbe(unittest.TestCase):
    def test_simple_struct_deref(self):
        text = """
#include <linux/blkdev.h>
#include <uapi/linux/ptrace.h>
int do_request(struct pt_regs *ctx, struct request *req) {
    bpf_trace_printk("%s\\n", req->rq_disk->disk_name);
    return 0;
}
"""
        b = bcc.BPF(text=text, debug=2, cflags=["-w"])
        b.attach_kprobe(event="blk_start_request", fn_name="do_request")

if __name__ == "__main__":
    unittest.main()

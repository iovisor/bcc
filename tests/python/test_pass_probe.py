#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

import bcc
import ctypes
import unittest

class TestPassProbe(unittest.TestCase):
    def tearDown(self):
        self.b.cleanup()

    def _test_simple_struct_deref(self):
        text = """
#include <linux/blkdev.h>
#include <uapi/linux/ptrace.h>
int do_request(struct pt_regs *ctx, struct request *req) {
    bpf_trace_printk("%s\\n", req->rq_disk->disk_name);
    return 0;
}
"""
        self.b = bcc.BPF(text=text, debug=3, cflags=["-w"])
        self.b.attach_kprobe(event="blk_start_request", fn_name="do_request")

    def test_builtin_memcpy(self):
        text = """
#include <linux/blkdev.h>
#include <uapi/linux/ptrace.h>
int do_request(struct pt_regs *ctx, struct request *req) {
    typeof(req->rq_disk->disk_name) copy;
    __builtin_memcpy(&copy, req->rq_disk->disk_name, DISK_NAME_LEN);
    bpf_trace_printk("%s\\n", copy);
    return 0;
}
"""
        self.b = bcc.BPF(text=text, debug=0, cflags=["-w"])
        self.b.attach_kprobe(event="blk_start_request", fn_name="do_request")
        self.b.trace_print()

#if __name__ == "__main__":
#    unittest.main()
TestPassProbe().test_builtin_memcpy()

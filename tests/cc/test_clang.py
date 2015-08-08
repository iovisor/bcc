#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bpf import BPF
from unittest import main, TestCase

class TestClang(TestCase):
    def test_complex(self):
        b = BPF(src_file="test_clang_complex.c", debug=0)
        fn = b.load_func("handle_packet", BPF.SCHED_CLS)
    def test_printk(self):
        text = """
#include <bcc/proto.h>
int handle_packet(void *ctx) {
  u8 *cursor = 0;
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  bpf_trace_printk("ethernet->dst = %llx, ethernet->src = %llx\\n",
                   ethernet->dst, ethernet->src);
  return 0;
}
"""
        b = BPF(text=text, debug=0)
        fn = b.load_func("handle_packet", BPF.SCHED_CLS)

    def test_probe_read1(self):
        text = """
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
int count_sched(struct pt_regs *ctx, struct task_struct *prev) {
    pid_t p = prev->pid;
    return (p != -1);
}
"""
        b = BPF(text=text, debug=0)
        fn = b.load_func("count_sched", BPF.KPROBE)

    def test_probe_read2(self):
        text = """
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
int count_foo(struct pt_regs *ctx, unsigned long a, unsigned long b) {
    return (a != b);
}
"""
        b = BPF(text=text, debug=0)
        fn = b.load_func("count_foo", BPF.KPROBE)

    def test_sscanf(self):
        text = """
BPF_TABLE("hash", int, struct { u64 a; u64 b; u64 c:31; u64 d:33; struct { u32 a; u32 b; } s; }, stats, 10);
int foo(void *ctx) {
    return 0;
}
"""
        b = BPF(text=text, debug=0)
        fn = b.load_func("foo", BPF.KPROBE)
        # todo: the actual test

if __name__ == "__main__":
    main()

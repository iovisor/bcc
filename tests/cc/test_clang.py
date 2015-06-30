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
  BEGIN(ethernet);
  PROTO(ethernet) {
    bpf_trace_printk("ethernet->dst = %llx, ethernet->src = %llx\\n",
                     ethernet->dst, ethernet->src);
  }
EOP:
  return 0;
}
"""
        b = BPF(text=text, debug=0)
        fn = b.load_func("handle_packet", BPF.SCHED_CLS)

if __name__ == "__main__":
    main()

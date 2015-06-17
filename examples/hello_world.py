#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# run in project directory with:
# sudo bash -c "PYTHONPATH=$PWD/src LD_LIBRARY_PATH=$PWD/build/src/cc examples/hello_world.py"

from bpf import BPF
from subprocess import call

prog = """
int hello(void *ctx) {
  bpf_trace_printk("Hello, World!\\n");
  return 0;
};
"""
b = BPF(text=prog)
fn = b.load_func("hello", BPF.KPROBE)
BPF.attach_kprobe(fn, "sys_clone")
try:
    call(["cat", "/sys/kernel/debug/tracing/trace_pipe"])
except KeyboardInterrupt:
    pass

#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# This is an example of tracing an event and printing custom fields.
# run in project examples directory with:
# sudo ./trace_fields.py"

import atexit
from bcc import BPF
import ctypes

counter = 0
def cb(foo, data, size):
    global counter
    counter += 1

prog = """
BPF_PERF_ARRAY(events, 2);
BPF_TABLE("array", int, u64, counters, 10);
int kprobe__sys_write(void *ctx) {
  struct {
    u64 ts;
  } data = {bpf_ktime_get_ns()};
  if (events.perf_output(ctx, 0, &data, sizeof(data)) < 0)
    bpf_trace_printk("perf_output failed\\n");
  int zero = 0;
  u64 *val = counters.lookup(&zero);
  if (val) lock_xadd(val, 1);
  return 0;
}
"""
b = BPF(text=prog)
b["events"].open_perf_buffer(0, cb, None)

@atexit.register
def print_counter():
    global counter
    global b
    print("counter = %d vs %d" % (counter, b["counters"][ctypes.c_int(0)].value))

while 1:
    b.kprobe_poll()

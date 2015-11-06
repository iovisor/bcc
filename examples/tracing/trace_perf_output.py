#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# This is an example of tracing an event and printing custom fields.
# run in project examples directory with:
# sudo ./trace_fields.py"

import atexit
from bcc import BPF
import ctypes
import multiprocessing

counter = 0
def cb(cookie, data, size):
    global counter
    counter += 1

prog = """
BPF_PERF_ARRAY(events, NUMCPU);
BPF_TABLE("array", int, u64, counters, 10);
int kprobe__sys_write(void *ctx) {
  struct {
    u64 ts;
  } data = {bpf_ktime_get_ns()};
  int rc;
  if ((rc = events.perf_output(ctx, bpf_get_smp_processor_id(), &data, sizeof(data))) < 0)
    bpf_trace_printk("perf_output failed: %d\\n", rc);
  int zero = 0;
  u64 *val = counters.lookup(&zero);
  if (val) lock_xadd(val, 1);
  return 0;
}
"""
numcpu = multiprocessing.cpu_count()
prog = prog.replace("NUMCPU", str(numcpu))
b = BPF(text=prog)
b["events"].open_perf_buffers(cb, None)

@atexit.register
def print_counter():
    global counter
    global b
    print("counter = %d vs %d" % (counter, b["counters"][ctypes.c_int(0)].value))

print("Tracing sys_write, try `dd if=/dev/zero of=/dev/null`")
print("Tracing... Hit Ctrl-C to end.")
while 1:
    b.kprobe_poll()

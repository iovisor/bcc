#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# run in project examples directory with:
# sudo ./hello_world.py"
# see trace_fields.py for a longer example

from bcc import BPF

BPF(text='void kprobe__sys_clone(void *ctx) { bpf_trace_printk("Hello, World!\\n"); }').trace_print()

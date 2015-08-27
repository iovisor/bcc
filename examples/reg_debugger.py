#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# This example shows how a BPF program can single step through the calculations
# in a single function. The use case in this scenario was to see the
# step-by-step math in an ipv6 multipath route selection to debug why the
# distribution was uneven.
# The address offsets are unstable, and should be used with the kernel
# assembler output side by side.

from bpf import BPF

def reg_printer(name, reg, wrap=""):
    fn = """
int {0}(struct pt_regs *ctx) {{
    return bpf_trace_printk("{1}=0x%llx\\n", {2}(ctx->{1}));
}}
"""
    return fn.format(name, reg, wrap)

regs = ["di", "si", "dx", "cx", "ax", "bx", "bp"]
regs += ["r%d" % i for i in range(8, 15)]


prog = """
#include <linux/ptrace.h>
"""
for r in regs:
    prog += reg_printer("print_%s" % r, r)
    prog += reg_printer("print_%s_net" % r, r, "bpf_ntohll")

b = BPF(text=prog)
b.attach_kprobe(event="rt6_multipath_select+0x1c", fn_name="print_r10")
b.attach_kprobe(event="rt6_multipath_select+0x20", fn_name="print_r10")
b.attach_kprobe(event="rt6_multipath_select+0x24", fn_name="print_r8")
b.attach_kprobe(event="rt6_multipath_select+0x28", fn_name="print_r8")
b.attach_kprobe(event="rt6_multipath_select+0x33", fn_name="print_di")
b.attach_kprobe(event="rt6_multipath_select+0x37", fn_name="print_r10")
b.attach_kprobe(event="rt6_multipath_select+0x3a", fn_name="print_di")
b.attach_kprobe(event="rt6_multipath_select+0x3e", fn_name="print_r8")
b.attach_kprobe(event="rt6_multipath_select+0x40", fn_name="print_di")
b.attach_kprobe(event="rt6_multipath_select+0x43", fn_name="print_di")
b.attach_kprobe(event="rt6_multipath_select+0x46", fn_name="print_di")
b.attach_kretprobe(event="rt6_multipath_select", fn_name="print_ax")
b.trace_print()

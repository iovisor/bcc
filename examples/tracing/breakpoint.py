#!/usr/bin/python

# This is an example of a hardware breakpoint on a kernel address.
# run in project examples directory with:
# sudo ./breakpoint.py"
# <0xaddress> <pid> <breakpoint_type>
# HW_BREAKPOINT_W = 2
# HW_BREAKPOINT_RW = 3

# You may need to clear the old tracepipe inputs before running the script : 
# echo > /sys/kernel/debug/tracing/trace 
 
# 10-Jul-2019   Aanandita Dhawan   Created this.

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

prog = """
#include <uapi/linux/ptrace.h>

int func(struct pt_regs *ctx) {
    bpf_trace_printk("Hello World, Here I accessed the address, Instr. ptr = 0x%p\\n", ctx->ip);
    return 0;
}
"""
b = BPF(text=prog)

symbol_addr = input()
pid = input()
bp_type = input()
b.attach_breakpoint(symbol_addr, pid, "func", bp_type)

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    except KeyboardInterrupt:
        break
    printb(b"%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))

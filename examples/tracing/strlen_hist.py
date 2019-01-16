#!/usr/bin/python

#
# strlen_hist.py   Histogram of system-wide strlen return values
#
# A basic example of using uprobes along with a histogram to show
# distributions.
#
# Runs until ctrl-c is pressed.
#
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# Example output:
# $ sudo ./strlen_hist.py
# 22:12:52
#      strlen return:      : count     distribution
#          0 -> 1          : 2106     |****************                        |
#          2 -> 3          : 1172     |*********                               |
#          4 -> 7          : 3892     |******************************          |
#          8 -> 15         : 5096     |****************************************|
#         16 -> 31         : 2201     |*****************                       |
#         32 -> 63         : 547      |****                                    |
#         64 -> 127        : 106      |                                        |
#        128 -> 255        : 13       |                                        |
#        256 -> 511        : 27       |                                        |
#        512 -> 1023       : 6        |                                        |
#       1024 -> 2047       : 10       |                                        |
# ^C$
#

from __future__ import print_function
import bcc
import time

text = """
#include <uapi/linux/ptrace.h>
BPF_HISTOGRAM(dist);
int count(struct pt_regs *ctx) {
    dist.increment(bpf_log2l(PT_REGS_RC(ctx)));
    return 0;
}
"""

b = bcc.BPF(text=text)
sym="strlen"
b.attach_uretprobe(name="c", sym=sym, fn_name="count")

dist = b["dist"]

try:
    while True:
        time.sleep(1)
        print("%-8s\n" % time.strftime("%H:%M:%S"), end="")
        dist.print_log2_hist(sym + " return:")
        dist.clear()

except KeyboardInterrupt:
    pass

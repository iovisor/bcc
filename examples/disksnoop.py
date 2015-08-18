#!/usr/bin/env python
#
# disksnoop.py	Trace block device I/O: basic version of iosnoop.
#		For Linux, uses BCC, eBPF. See .c file.
#
# Written as a basic example of tracing latency.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 11-Aug-2015	Brendan Gregg	Created this.

from bpf import BPF
import sys

REQ_WRITE = 1		# from include/linux/blk_types.h

# load BPF program
b = BPF(src_file="disksnoop.c")
BPF.attach_kprobe(b.load_func("do_request", BPF.KPROBE), "blk_start_request")
BPF.attach_kprobe(b.load_func("do_completion", BPF.KPROBE), "blk_update_request")

# header
print "%-18s %-2s %-7s %8s" % ("TIME(s)", "T", "BYTES", "LAT(ms)")

# open trace pipe
try:
	trace = open("/sys/kernel/debug/tracing/trace_pipe", "r")
except:
	print >> sys.stderr, "ERROR: opening trace_pipe"
	exit(1)

# format output
while 1:
	try:
		line = trace.readline().rstrip()
	except KeyboardInterrupt:
		pass; exit()
	prolog, time_s, colon, bytes_s, flags_s, us_s = \
		line.rsplit(" ", 5)

	time_s = time_s[:-1]	# strip trailing ":"
	flags = int(flags_s, 16)
	if flags & REQ_WRITE:
		type_s = "W"
	elif bytes_s == "0":	# see blk_fill_rwbs() for logic
		type_s = "M"
	else:
		type_s = "R"
	ms = float(int(us_s, 10)) / 1000

	print "%-18s %-2s %-7s %8.2f" % (time_s, type_s, bytes_s, ms)

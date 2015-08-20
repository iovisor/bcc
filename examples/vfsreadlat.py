#!/usr/bin/python
#
# vfsreadlat.py		VFS read latency distribution.
#			For Linux, uses BCC, eBPF. See .c file.
#
# Written as a basic example of a function latency distribution histogram.
#
# USAGE: vfsreadlat.py [interval [count]]
#
# The default interval is 5 seconds. A Ctrl-C will print the partially
# gathered histogram then exit.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 15-Aug-2015	Brendan Gregg	Created this.

from bpf import BPF
from ctypes import c_ushort, c_int, c_ulonglong
from time import sleep
from sys import argv

def usage():
	print("USAGE: %s [interval [count]]" % argv[0])
	exit()

# arguments
interval = 5
count = -1
if len(argv) > 1:
	try:
		interval = int(argv[1])
		if interval == 0:
			raise
		if len(argv) > 2:
			count = int(argv[2])
	except:	# also catches -h, --help
		usage()

# load BPF program
b = BPF(src_file = "vfsreadlat.c")
b.attach_kprobe(event="vfs_read", fn_name="do_entry")
b.attach_kretprobe(event="vfs_read", fn_name="do_return")
dist_max = 64

# header
print("Tracing... Hit Ctrl-C to end.")
last = {}
for i in range(1, dist_max + 1):
	last[i] = 0

# functions
stars_max = 38
def stars(val, val_max, width):
	i = 0
	text = ""
	while (1):
		if (i > (width * val / val_max) - 1) or (i > width - 1):
			break
		text += "*"
		i += 1
	if val > val_max:
		text = text[:-1] + "+"
	return text

def print_log2_hist(d, val_type):
	idx_max = -1
	val_max = 0
	for i in range(1, dist_max + 1):
		try:
			val = b["dist"][c_int(i)].value - last[i]
			if (val > 0):
				idx_max = i
			if (val > val_max):
				val_max = val
		except:
			break
	if idx_max > 0:
		print("     %-15s : count     distribution" % val_type);
	for i in range(1, idx_max + 1):
		low = (1 << i) >> 1
		high = (1 << i) - 1
		if (low == high):
			low -= 1
		try:
			val = b["dist"][c_int(i)].value - last[i]
			print("%8d -> %-8d : %-8d |%-*s|" % (low, high, val,
			    stars_max, stars(val, val_max, stars_max)))
			last[i] = b["dist"][c_int(i)].value
		except:
			break

# output
loop = 0
do_exit = 0
while (1):
	if count > 0:
		loop += 1
		if loop > count:
			exit()
	try:
		sleep(interval)
	except KeyboardInterrupt:
		pass; do_exit = 1

	print
	print_log2_hist(b["dist"], "usecs")
	if do_exit:
		exit()

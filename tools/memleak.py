#!/usr/bin/env python

from bcc import BPF
from time import sleep
import argparse
import subprocess
import ctypes
import os

class Time(object):
	# Adapted from http://stackoverflow.com/a/1205762
	CLOCK_MONOTONIC_RAW = 4 # see <linux/time.h>

	class timespec(ctypes.Structure):
		_fields_ = [
			('tv_sec', ctypes.c_long),
			('tv_nsec', ctypes.c_long)
		]

	librt = ctypes.CDLL('librt.so.1', use_errno=True)
	clock_gettime = librt.clock_gettime
	clock_gettime.argtypes = [ctypes.c_int, ctypes.POINTER(timespec)]

	@staticmethod
	def monotonic_time():
		"""monotonic_time()
		Returns the reading of the monotonic clock, in nanoseconds.
		"""
		t = Time.timespec()
		if Time.clock_gettime(Time.CLOCK_MONOTONIC_RAW , ctypes.pointer(t)) != 0:
			errno_ = ctypes.get_errno()
			raise OSError(errno_, os.strerror(errno_))
		return t.tv_sec*1e9 + t.tv_nsec

examples = """
EXAMPLES:

./memleak.py -p $(pidof allocs)
	Trace allocations and display a summary of "leaked" (outstanding)
	allocations every 5 seconds
./memleak.py -p $(pidof allocs) -t
	Trace allocations and display each individual call to malloc/free
./memleak.py -p $(pidof allocs) -a -i 10
	Trace allocations and display allocated addresses, sizes, and stacks
	every 10 seconds for outstanding allocations
./memleak.py
	Trace allocations in kernel mode and display a summary of outstanding
	allocations every 5 seconds
./memleak.py -o 60000
	Trace allocations in kernel mode and display a summary of outstanding
	allocations that are at least one minute (60 seconds) old
"""

description = """
Trace outstanding memory allocations that weren't freed.
Supports both user-mode allocations made with malloc/free and kernel-mode
allocations made with kmalloc/kfree.
"""

parser = argparse.ArgumentParser(description=description,
	formatter_class=argparse.RawDescriptionHelpFormatter,
	epilog=examples)
parser.add_argument("-p", "--pid",
	help="the PID to trace; if not specified, trace kernel allocs")
parser.add_argument("-t", "--trace", action="store_true",
	help="print trace messages for each alloc/free call")
parser.add_argument("-i", "--interval", default=5,
	help="interval in seconds to print outstanding allocations")
parser.add_argument("-a", "--show-allocs", default=False, action="store_true",
	help="show allocation addresses and sizes as well as call stacks")
parser.add_argument("-o", "--older", default=500,
	help="prune allocations younger than this age in milliseconds")
# TODO Run a command and trace that command (-c)

args = parser.parse_args()

pid = -1 if args.pid is None else int(args.pid)
kernel_trace = (pid == -1)
trace_all = args.trace
interval = int(args.interval)
min_age_ns = 1e6*int(args.older)

bpf_source = open("memleak.c").read()
bpf_source = bpf_source.replace("SHOULD_PRINT", "1" if trace_all else "0")

bpf_program = BPF(text=bpf_source)

if not kernel_trace:
	print("Attaching to malloc and free in pid %d, Ctrl+C to quit." % pid)
	bpf_program.attach_uprobe(name="c", sym="malloc", fn_name="alloc_enter", pid=pid)
	bpf_program.attach_uretprobe(name="c", sym="malloc", fn_name="alloc_exit", pid=pid)
	bpf_program.attach_uprobe(name="c", sym="free", fn_name="free_enter", pid=pid)
else:
	print("Attaching to kmalloc and kfree, Ctrl+C to quit.")
	bpf_program.attach_kprobe(event="__kmalloc", fn_name="alloc_enter")
	bpf_program.attach_kretprobe(event="__kmalloc", fn_name="alloc_exit")
	bpf_program.attach_kprobe(event="kfree", fn_name="free_enter")

def get_code_ranges(pid):
	ranges = {}
	raw_ranges = open("/proc/%d/maps" % pid).readlines()
	for raw_range in raw_ranges:
		parts = raw_range.split()
		if len(parts) < 6 or parts[5][0] == '[' or not 'x' in parts[1]:
			continue
		binary = parts[5]
		range_parts = parts[0].split('-')
		addr_range = (int(range_parts[0], 16), int(range_parts[1], 16))
		ranges[binary] = addr_range
	return ranges

def run_command(command):
	p = subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	return iter(p.stdout.readline, b'')

ranges_cache = {}

def get_sym_ranges(binary):
	if binary in ranges_cache:
		return ranges_cache[binary]
	sym_ranges = {}
	raw_symbols = run_command("objdump -t %s" % binary)
	for raw_symbol in raw_symbols:
		parts = raw_symbol.split()
		if len(parts) < 6 or parts[3] != ".text" or parts[2] != "F":
			continue
		sym_start = int(parts[0], 16)
		sym_len = int(parts[4], 16)
		sym_name = parts[5]
		sym_ranges[sym_name] = (sym_start, sym_len)
	ranges_cache[binary] = sym_ranges
	return sym_ranges

def decode_sym(binary, offset):
	sym_ranges = get_sym_ranges(binary)
	for name, (start, length) in sym_ranges.items():
		if offset >= start and offset <= (start + length):
			return "%s+0x%x" % (name, offset - start)
	return "%x" % offset

def decode_addr(code_ranges, addr):
	for binary, (start, end) in code_ranges.items():
		if addr >= start and addr <= end:
			offset = addr - start if binary.endswith(".so") else addr
			return "%s [%s]" % (decode_sym(binary, offset), binary)
	return "%x" % addr

def decode_stack(info):
	stack = ""
	if info.num_frames <= 0:
		return "???"
	for i in range(0, info.num_frames):
		addr = info.callstack[i]
		if kernel_trace:
			stack += " %s [kernel] (%x) ;" % (bpf_program.ksym(addr), addr)
		else:
			stack += " %s (%x) ;" % (decode_addr(code_ranges, addr), addr)
	return stack

def print_outstanding():
	stacks = {}
	print("*** Outstanding allocations:")
	allocs = bpf_program.get_table("allocs")
	for address, info in sorted(allocs.items(), key=lambda a: -a[1].size):
		if Time.monotonic_time() - min_age_ns < info.timestamp_ns:
			continue
		stack = decode_stack(info)
		if stack in stacks: stacks[stack] = (stacks[stack][0] + 1, stacks[stack][1] + info.size)
		else:               stacks[stack] = (1, info.size)
		if args.show_allocs:
			print("\taddr = %x size = %s" % (address.value, info.size))
	for stack, (count, size) in sorted(stacks.items(), key=lambda s: -s[1][1]):
		print("\t%d bytes in %d allocations from stack\n\t\t%s" % (size, count, stack.replace(";", "\n\t\t")))

while True:
        if trace_all:
		print bpf_program.trace_fields()
	else:
		try:
			sleep(interval)
		except KeyboardInterrupt:
			exit()
		if not kernel_trace:
			code_ranges = get_code_ranges(pid)
		print_outstanding()


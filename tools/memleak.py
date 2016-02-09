#!/usr/bin/env python

from bcc import BPF
from time import sleep
import argparse
import subprocess
import ctypes
import os

class Time(object):
        # BPF timestamps come from the monotonic clock. To be able to filter
        # and compare them from Python, we need to invoke clock_gettime.
        # Adapted from http://stackoverflow.com/a/1205762
        CLOCK_MONOTONIC_RAW = 4         # see <linux/time.h>

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
                t = Time.timespec()
                if Time.clock_gettime(
                        Time.CLOCK_MONOTONIC_RAW, ctypes.pointer(t)) != 0:
                        errno_ = ctypes.get_errno()
                        raise OSError(errno_, os.strerror(errno_))
                return t.tv_sec * 1e9 + t.tv_nsec

class StackDecoder(object):
        def __init__(self, pid, bpf):
                self.pid = pid
                self.bpf = bpf
                self.ranges_cache = {}
                self.refresh_code_ranges()

        def refresh_code_ranges(self):
                if self.pid == -1:
                        return
                self.code_ranges = self._get_code_ranges()

        @staticmethod
        def _is_binary_segment(parts):
                return len(parts) == 6 and \
                        parts[5][0] != '[' and 'x' in parts[1]

        def _get_code_ranges(self):
                ranges = {}
                raw_ranges = open("/proc/%d/maps" % self.pid).readlines()
                # A typical line from /proc/PID/maps looks like this:
                # 7f21b6635000-7f21b67eb000 r-xp ... /usr/lib64/libc-2.21.so
                # We are looking for executable segments that have a .so file
                # or the main executable. The first two lines are the range of
                # that memory segment, which we index by binary name.
                for raw_range in raw_ranges:
                        parts = raw_range.split()
                        if not StackDecoder._is_binary_segment(parts):
                                continue
                        binary = parts[5]
                        range_parts = parts[0].split('-')
                        addr_range = (int(range_parts[0], 16),
                                      int(range_parts[1], 16))
                        ranges[binary] = addr_range
                return ranges

        @staticmethod
        def _is_function_symbol(parts):
                return len(parts) == 6 and parts[3] == ".text" \
                        and parts[2] == "F"

        def _get_sym_ranges(self, binary):
                if binary in self.ranges_cache:
                        return self.ranges_cache[binary]
                sym_ranges = {}
                raw_symbols = run_command_get_output("objdump -t %s" % binary)
                for raw_symbol in raw_symbols:
                        # A typical line from objdump -t looks like this:
                        # 00000000004007f5 g F .text 000000000000010e main
                        # We only care about functions in the .text segment.
                        # The first number is the start address, and the second
                        # number is the length.
                        parts = raw_symbol.split()
                        if not StackDecoder._is_function_symbol(parts):
                                continue
                        sym_start = int(parts[0], 16)
                        sym_len = int(parts[4], 16)
                        sym_name = parts[5]
                        sym_ranges[sym_name] = (sym_start, sym_len)
                self.ranges_cache[binary] = sym_ranges
                return sym_ranges

        def _decode_sym(self, binary, offset):
                sym_ranges = self._get_sym_ranges(binary)
                # Find the symbol that contains the specified offset.
                # There might not be one.
                for name, (start, length) in sym_ranges.items():
                        if offset >= start and offset <= (start + length):
                                return "%s+0x%x" % (name, offset - start)
                return "%x" % offset

        def _decode_addr(self, addr):
                code_ranges = self._get_code_ranges()
                # Find the binary that contains the specified address.
                # For .so files, look at the relative address; for the main
                # executable, look at the absolute address.
                for binary, (start, end) in code_ranges.items():
                        if addr >= start and addr <= end:
                                offset = addr - start \
                                        if binary.endswith(".so") else addr
                                return "%s [%s]" % (self._decode_sym(binary,
                                        offset), binary)
                return "%x" % addr

        def decode_stack(self, info, is_kernel_trace):
                stack = ""
                if info.num_frames <= 0:
                        return "???"
                for i in range(0, info.num_frames):
                        addr = info.callstack[i]
                        if is_kernel_trace:
                                stack += " %s [kernel] (%x) ;" % \
                                        (self.bpf.ksym(addr), addr)
                        else:
                                # At some point, we hope to have native BPF
                                # user-mode symbol decoding, but for now we
                                # have to use our own.
                                stack += " %s (%x) ;" % \
                                        (self._decode_addr(addr), addr)
                return stack

def run_command_get_output(command):
        p = subprocess.Popen(command.split(),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return iter(p.stdout.readline, b'')

def run_command_get_pid(command):
        p = subprocess.Popen(command.split())
        return p.pid

examples = """
EXAMPLES:

./memleak.py -p $(pidof allocs)
        Trace allocations and display a summary of "leaked" (outstanding)
        allocations every 5 seconds
./memleak.py -p $(pidof allocs) -t
        Trace allocations and display each individual call to malloc/free
./memleak.py -ap $(pidof allocs) 10
        Trace allocations and display allocated addresses, sizes, and stacks
        every 10 seconds for outstanding allocations
./memleak.py -c "./allocs"
        Run the specified command and trace its allocations
./memleak.py
        Trace allocations in kernel mode and display a summary of outstanding
        allocations every 5 seconds
./memleak.py -o 60000
        Trace allocations in kernel mode and display a summary of outstanding
        allocations that are at least one minute (60 seconds) old
./memleak.py -s 5
        Trace roughly every 5th allocation, to reduce overhead
"""

description = """
Trace outstanding memory allocations that weren't freed.
Supports both user-mode allocations made with malloc/free and kernel-mode
allocations made with kmalloc/kfree.
"""

parser = argparse.ArgumentParser(description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
parser.add_argument("-p", "--pid", type=int, default=-1,
        help="the PID to trace; if not specified, trace kernel allocs")
parser.add_argument("-t", "--trace", action="store_true",
        help="print trace messages for each alloc/free call")
parser.add_argument("interval", nargs="?", default=5, type=int,
        help="interval in seconds to print outstanding allocations")
parser.add_argument("count", nargs="?", type=int,
        help="number of times to print the report before exiting")
parser.add_argument("-a", "--show-allocs", default=False, action="store_true",
        help="show allocation addresses and sizes as well as call stacks")
parser.add_argument("-o", "--older", default=500, type=int,
        help="prune allocations younger than this age in milliseconds")
parser.add_argument("-c", "--command",
        help="execute and trace the specified command")
parser.add_argument("-s", "--sample-rate", default=1, type=int,
        help="sample every N-th allocation to decrease the overhead")
parser.add_argument("-d", "--stack-depth", default=10, type=int,
        help="maximum stack depth to capture")

args = parser.parse_args()

pid = args.pid
command = args.command
kernel_trace = (pid == -1 and command is None)
trace_all = args.trace
interval = args.interval
min_age_ns = 1e6 * args.older
sample_every_n = args.sample_rate
num_prints = args.count
max_stack_size = args.stack_depth + 2

if command is not None:
        print("Executing '%s' and tracing the resulting process." % command)
        pid = run_command_get_pid(command)

bpf_source = open("memleak.c").read()
bpf_source = bpf_source.replace("SHOULD_PRINT", "1" if trace_all else "0")
bpf_source = bpf_source.replace("SAMPLE_EVERY_N", str(sample_every_n))
bpf_source = bpf_source.replace("GRAB_ONE_FRAME", max_stack_size *
        "\tif (!(info->callstack[depth++] = get_frame(&bp))) return depth;\n")
bpf_source = bpf_source.replace("MAX_STACK_SIZE", str(max_stack_size))
bpf_program = BPF(text=bpf_source)

if not kernel_trace:
        print("Attaching to malloc and free in pid %d, Ctrl+C to quit." % pid)
        bpf_program.attach_uprobe(name="c", sym="malloc",
                                  fn_name="alloc_enter", pid=pid)
        bpf_program.attach_uretprobe(name="c", sym="malloc",
                                     fn_name="alloc_exit", pid=pid)
        bpf_program.attach_uprobe(name="c", sym="free",
                                  fn_name="free_enter", pid=pid)
else:
        print("Attaching to kmalloc and kfree, Ctrl+C to quit.")
        bpf_program.attach_kprobe(event="__kmalloc", fn_name="alloc_enter")
        bpf_program.attach_kretprobe(event="__kmalloc", fn_name="alloc_exit")
        bpf_program.attach_kprobe(event="kfree", fn_name="free_enter")

decoder = StackDecoder(pid, bpf_program)

def print_outstanding():
        stacks = {}
        print("*** Outstanding allocations:")
        allocs = bpf_program.get_table("allocs")
        for address, info in sorted(allocs.items(), key=lambda a: a[1].size):
                if Time.monotonic_time() - min_age_ns < info.timestamp_ns:
                        continue
                stack = decoder.decode_stack(info, kernel_trace)
                if stack in stacks:
                        stacks[stack] = (stacks[stack][0] + 1,
                                         stacks[stack][1] + info.size)
                else:
                        stacks[stack] = (1, info.size)
                if args.show_allocs:
                        print("\taddr = %x size = %s" %
                              (address.value, info.size))
        for stack, (count, size) in sorted(stacks.items(),
                                           key=lambda s: s[1][1]):
                print("\t%d bytes in %d allocations from stack\n\t\t%s" %
                      (size, count, stack.replace(";", "\n\t\t")))

count_so_far = 0
while True:
        if trace_all:
                print bpf_program.trace_fields()
        else:
                try:
                        sleep(interval)
                except KeyboardInterrupt:
                        exit()
                decoder.refresh_code_ranges()
                print_outstanding()
                count_so_far += 1
                if num_prints is not None and count_so_far >= num_prints:
                        exit()

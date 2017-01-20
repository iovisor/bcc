#!/usr/bin/env python
#
# memleak   Trace and display outstanding allocations to detect
#           memory leaks in user-mode processes and the kernel.
#
# USAGE: memleak [-h] [-p PID] [-t] [-a] [-o OLDER] [-c COMMAND]
#                [-s SAMPLE_RATE] [-d STACK_DEPTH] [-T TOP] [-z MIN_SIZE]
#                [-Z MAX_SIZE]
#                [interval] [count]
#
# Licensed under the Apache License, Version 2.0 (the "License")
# Copyright (C) 2016 Sasha Goldshtein.

from bcc import BPF, ProcessSymbols
from time import sleep
from datetime import datetime
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

class KStackDecoder(object):
        def refresh(self):
                pass

        def __call__(self, addr):
                return "%s [kernel] (%x)" % (BPF.ksym(addr), addr)

class UStackDecoder(object):
        def __init__(self, pid):
                self.pid = pid
                self.proc_sym = ProcessSymbols(pid)

        def refresh(self):
                self.proc_sym.refresh_code_ranges()

        def __call__(self, addr):
                return "%s (%x)" % (self.proc_sym.decode_addr(addr), addr)

class Allocation(object):
    def __init__(self, stack, size):
        self.stack = stack
        self.count = 1
        self.size = size

    def update(self, size):
        self.count += 1
        self.size += size

def run_command_get_output(command):
        p = subprocess.Popen(command.split(),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return iter(p.stdout.readline, b'')

def run_command_get_pid(command):
        p = subprocess.Popen(command.split())
        return p.pid

examples = """
EXAMPLES:

./memleak -p $(pidof allocs)
        Trace allocations and display a summary of "leaked" (outstanding)
        allocations every 5 seconds
./memleak -p $(pidof allocs) -t
        Trace allocations and display each individual call to malloc/free
./memleak -ap $(pidof allocs) 10
        Trace allocations and display allocated addresses, sizes, and stacks
        every 10 seconds for outstanding allocations
./memleak -c "./allocs"
        Run the specified command and trace its allocations
./memleak
        Trace allocations in kernel mode and display a summary of outstanding
        allocations every 5 seconds
./memleak -o 60000
        Trace allocations in kernel mode and display a summary of outstanding
        allocations that are at least one minute (60 seconds) old
./memleak -s 5
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
parser.add_argument("-T", "--top", type=int, default=10,
        help="display only this many top allocating stacks (by size)")
parser.add_argument("-z", "--min-size", type=int,
        help="capture only allocations larger than this size")
parser.add_argument("-Z", "--max-size", type=int,
        help="capture only allocations smaller than this size")
parser.add_argument("-O", "--obj", type=str, default="c",
        help="attach to malloc & free in the specified object")

args = parser.parse_args()

pid = args.pid
command = args.command
kernel_trace = (pid == -1 and command is None)
trace_all = args.trace
interval = args.interval
min_age_ns = 1e6 * args.older
sample_every_n = args.sample_rate
num_prints = args.count
top_stacks = args.top
min_size = args.min_size
max_size = args.max_size
obj = args.obj

if min_size is not None and max_size is not None and min_size > max_size:
        print("min_size (-z) can't be greater than max_size (-Z)")
        exit(1)

if command is not None:
        print("Executing '%s' and tracing the resulting process." % command)
        pid = run_command_get_pid(command)

bpf_source = """
#include <uapi/linux/ptrace.h>

struct alloc_info_t {
        u64 size;
        u64 timestamp_ns;
        int stack_id;
};

BPF_HASH(sizes, u64);
BPF_HASH(allocs, u64, struct alloc_info_t);
BPF_STACK_TRACE(stack_traces, 1024)

int alloc_enter(struct pt_regs *ctx, size_t size)
{
        SIZE_FILTER
        if (SAMPLE_EVERY_N > 1) {
                u64 ts = bpf_ktime_get_ns();
                if (ts % SAMPLE_EVERY_N != 0)
                        return 0;
        }

        u64 pid = bpf_get_current_pid_tgid();
        u64 size64 = size;
        sizes.update(&pid, &size64);

        if (SHOULD_PRINT)
                bpf_trace_printk("alloc entered, size = %u\\n", size);
        return 0;
}

int alloc_exit(struct pt_regs *ctx)
{
        u64 address = PT_REGS_RC(ctx);
        u64 pid = bpf_get_current_pid_tgid();
        u64* size64 = sizes.lookup(&pid);
        struct alloc_info_t info = {0};

        if (size64 == 0)
                return 0; // missed alloc entry

        info.size = *size64;
        sizes.delete(&pid);

        info.timestamp_ns = bpf_ktime_get_ns();
        info.stack_id = stack_traces.get_stackid(ctx, STACK_FLAGS);
        allocs.update(&address, &info);

        if (SHOULD_PRINT) {
                bpf_trace_printk("alloc exited, size = %lu, result = %lx\\n",
                                 info.size, address);
        }
        return 0;
}

int free_enter(struct pt_regs *ctx, void *address)
{
        u64 addr = (u64)address;
        struct alloc_info_t *info = allocs.lookup(&addr);
        if (info == 0)
                return 0;

        allocs.delete(&addr);

        if (SHOULD_PRINT) {
                bpf_trace_printk("free entered, address = %lx, size = %lu\\n",
                                 address, info->size);
        }
        return 0;
}
"""
bpf_source = bpf_source.replace("SHOULD_PRINT", "1" if trace_all else "0")
bpf_source = bpf_source.replace("SAMPLE_EVERY_N", str(sample_every_n))

size_filter = ""
if min_size is not None and max_size is not None:
        size_filter = "if (size < %d || size > %d) return 0;" % \
                      (min_size, max_size)
elif min_size is not None:
        size_filter = "if (size < %d) return 0;" % min_size
elif max_size is not None:
        size_filter = "if (size > %d) return 0;" % max_size
bpf_source = bpf_source.replace("SIZE_FILTER", size_filter)

stack_flags = "BPF_F_REUSE_STACKID"
if not kernel_trace:
        stack_flags += "|BPF_F_USER_STACK"
bpf_source = bpf_source.replace("STACK_FLAGS", stack_flags)

bpf_program = BPF(text=bpf_source)

if not kernel_trace:
        print("Attaching to malloc and free in pid %d, Ctrl+C to quit." % pid)
        bpf_program.attach_uprobe(name=obj, sym="malloc",
                                  fn_name="alloc_enter", pid=pid)
        bpf_program.attach_uretprobe(name=obj, sym="malloc",
                                     fn_name="alloc_exit", pid=pid)
        bpf_program.attach_uprobe(name=obj, sym="free",
                                  fn_name="free_enter", pid=pid)
else:
        print("Attaching to kmalloc and kfree, Ctrl+C to quit.")
        bpf_program.attach_kprobe(event="__kmalloc", fn_name="alloc_enter")
        bpf_program.attach_kretprobe(event="__kmalloc", fn_name="alloc_exit")
        bpf_program.attach_kprobe(event="kfree", fn_name="free_enter")

decoder = KStackDecoder() if kernel_trace else UStackDecoder(pid)

def print_outstanding():
        print("[%s] Top %d stacks with outstanding allocations:" %
              (datetime.now().strftime("%H:%M:%S"), top_stacks))
        alloc_info = {}
        allocs = bpf_program["allocs"]
        stack_traces = bpf_program["stack_traces"]
        for address, info in sorted(allocs.items(), key=lambda a: a[1].size):
                if Time.monotonic_time() - min_age_ns < info.timestamp_ns:
                        continue
                if info.stack_id < 0:
                        continue
                if info.stack_id in alloc_info:
                        alloc_info[info.stack_id].update(info.size)
                else:
                        stack = list(stack_traces.walk(info.stack_id, decoder))
                        alloc_info[info.stack_id] = Allocation(stack,
                                                               info.size)
                if args.show_allocs:
                        print("\taddr = %x size = %s" %
                              (address.value, info.size))
        to_show = sorted(alloc_info.values(),
                         key=lambda a: a.size)[-top_stacks:]
        for alloc in to_show:
                print("\t%d bytes in %d allocations from stack\n\t\t%s" %
                      (alloc.size, alloc.count, "\n\t\t".join(alloc.stack)))

count_so_far = 0
while True:
        if trace_all:
                print(bpf_program.trace_fields())
        else:
                try:
                        sleep(interval)
                except KeyboardInterrupt:
                        exit()
                decoder.refresh()
                print_outstanding()
                count_so_far += 1
                if num_prints is not None and count_so_far >= num_prints:
                        exit()

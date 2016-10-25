#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# uthreads  Trace thread creation/destruction events in high-level languages.
#           For Linux, uses BCC, eBPF.
#
# USAGE: uthreads {java} PID [-v]
#
# Copyright 2016 Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 25-Oct-2016   Sasha Goldshtein   Created this.

from __future__ import print_function
import argparse
from bcc import BPF, USDT
import ctypes as ct
import time

examples = """examples:
    ./uthreads java 185   # trace Java threads in process 185
"""
parser = argparse.ArgumentParser(
    description="Trace thread creation/destruction events in " +
                "high-level languages.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("language", choices=["java"],
    help="language to trace")
parser.add_argument("pid", type=int, help="process id to attach to")
parser.add_argument("-v", "--verbose", action="store_true",
    help="verbose mode: print the BPF program (for debugging purposes)")
args = parser.parse_args()

usdt = USDT(pid=args.pid)

program = """
struct thread_event_t {
    u64 runtime_id;
    u64 native_id;
    char type[8];
    char name[80];
};

BPF_PERF_OUTPUT(threads);
"""

if args.language == "java":
    template = """
int %s(struct pt_regs *ctx) {
    char description[] = "%s";
    struct thread_event_t te = {};
    u64 nameptr = 0, id = 0, native_id = 0;
    bpf_usdt_readarg(1, ctx, &nameptr);
    bpf_usdt_readarg(3, ctx, &id);
    bpf_usdt_readarg(4, ctx, &native_id);
    bpf_probe_read(&te.name, sizeof(te.name), (void *)nameptr);
    te.runtime_id = id;
    te.native_id = native_id;
    __builtin_memcpy(&te.type, description, sizeof(te.type));
    threads.perf_submit(ctx, &te, sizeof(te));
    return 0;
}
    """
    program += template % ("trace_start", "start")
    program += template % ("trace_stop", "stop")
    usdt.enable_probe("thread__start", "trace_start")
    usdt.enable_probe("thread__stop", "trace_stop")

if args.verbose:
    print(usdt.get_text())
    print(program)

bpf = BPF(text=program, usdt_contexts=[usdt])
print("Tracing thread events in %s process %d... Ctrl-C to quit." %
      (args.language, args.pid))
print("%-8s %-16s %-8s %-30s" % ("TIME", "ID", "TYPE", "DESCRIPTION"))

class ThreadEvent(ct.Structure):
    _fields_ = [
        ("runtime_id", ct.c_ulonglong),
        ("native_id", ct.c_ulonglong),
        ("type", ct.c_char * 8),
        ("name", ct.c_char * 80),
        ]

start_ts = time.time()

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(ThreadEvent)).contents
    print("%-8.3f %-16s %-8s %-30s" % (
        time.time() - start_ts, "%s/%s" % (event.runtime_id, event.native_id),
        event.type, event.name))

bpf["threads"].open_perf_buffer(print_event)
while 1:
    bpf.kprobe_poll()

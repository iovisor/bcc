#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# uthreads  Trace thread creation/destruction events in high-level languages.
#           For Linux, uses BCC, eBPF.
#
# USAGE: uthreads [-l {c,java,none}] [-v] pid
#
# Copyright 2016 Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 25-Oct-2016   Sasha Goldshtein   Created this.

from __future__ import print_function
import argparse
from bcc import BPF, USDT, utils
import ctypes as ct
import time
import os

languages = ["c", "java"]

examples = """examples:
    ./uthreads -l java 185    # trace Java threads in process 185
    ./uthreads -l none 12245  # trace only pthreads in process 12245
"""
parser = argparse.ArgumentParser(
    description="Trace thread creation/destruction events in " +
                "high-level languages.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-l", "--language", choices=languages + ["none"],
    help="language to trace (none for pthreads only)")
parser.add_argument("pid", type=int, help="process id to attach to")
parser.add_argument("-v", "--verbose", action="store_true",
    help="verbose mode: print the BPF program (for debugging purposes)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
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

int trace_pthread(struct pt_regs *ctx) {
    struct thread_event_t te = {};
    u64 start_routine = 0;
    char type[] = "pthread";
    te.native_id = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_usdt_readarg(2, ctx, &start_routine);
    te.runtime_id = start_routine;  // This is really a function pointer
    __builtin_memcpy(&te.type, type, sizeof(te.type));
    threads.perf_submit(ctx, &te, sizeof(te));
    return 0;
}
"""
usdt.enable_probe_or_bail("pthread_start", "trace_pthread")

language = args.language
if not language:
    language = utils.detect_language(languages, args.pid)

if language == "c":
    # Nothing to add
    pass
elif language == "java":
    template = """
int %s(struct pt_regs *ctx) {
    char type[] = "%s";
    struct thread_event_t te = {};
    u64 nameptr = 0, id = 0, native_id = 0;
    bpf_usdt_readarg(1, ctx, &nameptr);
    bpf_usdt_readarg(3, ctx, &id);
    bpf_usdt_readarg(4, ctx, &native_id);
    bpf_probe_read(&te.name, sizeof(te.name), (void *)nameptr);
    te.runtime_id = id;
    te.native_id = native_id;
    __builtin_memcpy(&te.type, type, sizeof(te.type));
    threads.perf_submit(ctx, &te, sizeof(te));
    return 0;
}
    """
    program += template % ("trace_start", "start")
    program += template % ("trace_stop", "stop")
    usdt.enable_probe_or_bail("thread__start", "trace_start")
    usdt.enable_probe_or_bail("thread__stop", "trace_stop")

if args.ebpf or args.verbose:
    if args.verbose:
        print(usdt.get_text())
    print(program)
    if args.ebpf:
        exit()

bpf = BPF(text=program, usdt_contexts=[usdt])
print("Tracing thread events in process %d (language: %s)... Ctrl-C to quit." %
      (args.pid, language or "none"))
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
    name = event.name
    if event.type == "pthread":
        name = bpf.sym(event.runtime_id, args.pid, show_module=True)
        tid = event.native_id
    else:
        tid = "R=%s/N=%s" % (event.runtime_id, event.native_id)
    print("%-8.3f %-16s %-8s %-30s" % (
        time.time() - start_ts, tid, event.type, name))

bpf["threads"].open_perf_buffer(print_event)
while 1:
    bpf.perf_buffer_poll()

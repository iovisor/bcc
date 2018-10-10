#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# uflow  Trace method execution flow in high-level languages.
#        For Linux, uses BCC, eBPF.
#
# USAGE: uflow [-C CLASS] [-M METHOD] [-v] {java,perl,php,python,ruby,tcl} pid
#
# Copyright 2016 Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 27-Oct-2016   Sasha Goldshtein   Created this.

from __future__ import print_function
import argparse
from bcc import BPF, USDT, utils
import ctypes as ct
import time
import os

languages = ["java", "perl", "php", "python", "ruby", "tcl"]

examples = """examples:
    ./uflow -l java 185                # trace Java method calls in process 185
    ./uflow -l ruby 134                # trace Ruby method calls in process 134
    ./uflow -M indexOf -l java 185     # trace only 'indexOf'-prefixed methods
    ./uflow -C '<stdin>' -l python 180 # trace only REPL-defined methods
"""
parser = argparse.ArgumentParser(
    description="Trace method execution flow in high-level languages.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-l", "--language", choices=languages,
    help="language to trace")
parser.add_argument("pid", type=int, help="process id to attach to")
parser.add_argument("-M", "--method",
    help="trace only calls to methods starting with this prefix")
parser.add_argument("-C", "--class", dest="clazz",
    help="trace only calls to classes starting with this prefix")
parser.add_argument("-v", "--verbose", action="store_true",
    help="verbose mode: print the BPF program (for debugging purposes)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

usdt = USDT(pid=args.pid)

program = """
struct call_t {
    u64 depth;                  // first bit is direction (0 entry, 1 return)
    u64 pid;                    // (tgid << 32) + pid from bpf_get_current...
    char clazz[80];
    char method[80];
};

BPF_PERF_OUTPUT(calls);
BPF_HASH(entry, u64, u64);
"""

prefix_template = """
static inline bool prefix_%s(char *actual) {
    char expected[] = "%s";
    for (int i = 0; i < sizeof(expected) - 1; ++i) {
        if (expected[i] != actual[i]) {
            return false;
        }
    }
    return true;
}
"""

if args.clazz:
    program += prefix_template % ("class", args.clazz)
if args.method:
    program += prefix_template % ("method", args.method)

trace_template = """
int NAME(struct pt_regs *ctx) {
    u64 *depth, zero = 0, clazz = 0, method = 0 ;
    struct call_t data = {};

    READ_CLASS
    READ_METHOD
    bpf_probe_read(&data.clazz, sizeof(data.clazz), (void *)clazz);
    bpf_probe_read(&data.method, sizeof(data.method), (void *)method);

    FILTER_CLASS
    FILTER_METHOD

    data.pid = bpf_get_current_pid_tgid();
    depth = entry.lookup_or_init(&data.pid, &zero);
    data.depth = DEPTH;
    UPDATE

    calls.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

def enable_probe(probe_name, func_name, read_class, read_method, is_return):
    global program, trace_template, usdt
    depth = "*depth + 1" if not is_return else "*depth | (1ULL << 63)"
    update = "++(*depth);" if not is_return else "if (*depth) --(*depth);"
    filter_class = "if (!prefix_class(data.clazz)) { return 0; }" \
                   if args.clazz else ""
    filter_method = "if (!prefix_method(data.method)) { return 0; }" \
                   if args.method else ""
    program += trace_template.replace("NAME", func_name)                \
                             .replace("READ_CLASS", read_class)         \
                             .replace("READ_METHOD", read_method)       \
                             .replace("FILTER_CLASS", filter_class)     \
                             .replace("FILTER_METHOD", filter_method)   \
                             .replace("DEPTH", depth)                   \
                             .replace("UPDATE", update)
    usdt.enable_probe_or_bail(probe_name, func_name)

usdt = USDT(pid=args.pid)

language = args.language
if not language:
    language = utils.detect_language(languages, args.pid)

if language == "java":
    enable_probe("method__entry", "java_entry",
                 "bpf_usdt_readarg(2, ctx, &clazz);",
                 "bpf_usdt_readarg(4, ctx, &method);", is_return=False)
    enable_probe("method__return", "java_return",
                 "bpf_usdt_readarg(2, ctx, &clazz);",
                 "bpf_usdt_readarg(4, ctx, &method);", is_return=True)
elif language == "perl":
    enable_probe("sub__entry", "perl_entry",
                 "bpf_usdt_readarg(2, ctx, &clazz);",
                 "bpf_usdt_readarg(1, ctx, &method);", is_return=False)
    enable_probe("sub__return", "perl_return",
                 "bpf_usdt_readarg(2, ctx, &clazz);",
                 "bpf_usdt_readarg(1, ctx, &method);", is_return=True)
elif language == "php":
    enable_probe("function__entry", "php_entry",
                 "bpf_usdt_readarg(4, ctx, &clazz);",
                 "bpf_usdt_readarg(1, ctx, &method);", is_return=False)
    enable_probe("function__return", "php_return",
                 "bpf_usdt_readarg(4, ctx, &clazz);",
                 "bpf_usdt_readarg(1, ctx, &method);", is_return=True)
elif language == "python":
    enable_probe("function__entry", "python_entry",
                 "bpf_usdt_readarg(1, ctx, &clazz);",   # filename really
                 "bpf_usdt_readarg(2, ctx, &method);", is_return=False)
    enable_probe("function__return", "python_return",
                 "bpf_usdt_readarg(1, ctx, &clazz);",   # filename really
                 "bpf_usdt_readarg(2, ctx, &method);", is_return=True)
elif language == "ruby":
    enable_probe("method__entry", "ruby_entry",
                 "bpf_usdt_readarg(1, ctx, &clazz);",
                 "bpf_usdt_readarg(2, ctx, &method);", is_return=False)
    enable_probe("method__return", "ruby_return",
                 "bpf_usdt_readarg(1, ctx, &clazz);",
                 "bpf_usdt_readarg(2, ctx, &method);", is_return=True)
    enable_probe("cmethod__entry", "ruby_centry",
                 "bpf_usdt_readarg(1, ctx, &clazz);",
                 "bpf_usdt_readarg(2, ctx, &method);", is_return=False)
    enable_probe("cmethod__return", "ruby_creturn",
                 "bpf_usdt_readarg(1, ctx, &clazz);",
                 "bpf_usdt_readarg(2, ctx, &method);", is_return=True)
elif language == "tcl":
    enable_probe("proc__args", "tcl_entry",
                 "",  # no class/file info available
                 "bpf_usdt_readarg(1, ctx, &method);", is_return=False)
    enable_probe("proc__return", "tcl_return",
                 "",  # no class/file info available
                 "bpf_usdt_readarg(1, ctx, &method);", is_return=True)
else:
    print("No language detected; use -l to trace a language.")
    exit(1)

if args.ebpf or args.verbose:
    if args.verbose:
        print(usdt.get_text())
    print(program)
    if args.ebpf:
        exit()

bpf = BPF(text=program, usdt_contexts=[usdt])
print("Tracing method calls in %s process %d... Ctrl-C to quit." %
      (language, args.pid))
print("%-3s %-6s %-6s %-8s %s" % ("CPU", "PID", "TID", "TIME(us)", "METHOD"))

class CallEvent(ct.Structure):
    _fields_ = [
        ("depth", ct.c_ulonglong),
        ("pid", ct.c_ulonglong),
        ("clazz", ct.c_char * 80),
        ("method", ct.c_char * 80)
        ]

start_ts = time.time()

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(CallEvent)).contents
    depth = event.depth & (~(1 << 63))
    direction = "<- " if event.depth & (1 << 63) else "-> "
    print("%-3d %-6d %-6d %-8.3f %-40s" % (cpu, event.pid >> 32,
        event.pid & 0xFFFFFFFF, time.time() - start_ts,
        ("  " * (depth - 1)) + direction + \
            event.clazz.decode('utf-8', 'replace') + "." + \
            event.method.decode('utf-8', 'replace')))

bpf["calls"].open_perf_buffer(print_event)
while 1:
    bpf.perf_buffer_poll()

#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# ugc  Summarize garbage collection events in high-level languages.
#      For Linux, uses BCC, eBPF.
#
# USAGE: ugc [-v] [-m] [-M MSEC] [-F FILTER] {java,node,python,ruby} pid
#
# Copyright 2016 Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 19-Oct-2016   Sasha Goldshtein   Created this.

from __future__ import print_function
import argparse
from bcc import BPF, USDT, utils
import ctypes as ct
import time
import os

languages = ["java", "node", "python", "ruby"]

examples = """examples:
    ./ugc -l java 185        # trace Java GCs in process 185
    ./ugc -l ruby 1344 -m    # trace Ruby GCs reporting in ms
    ./ugc -M 10 -l java 185  # trace only Java GCs longer than 10ms
"""
parser = argparse.ArgumentParser(
    description="Summarize garbage collection events in high-level languages.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-l", "--language", choices=languages,
    help="language to trace")
parser.add_argument("pid", type=int, help="process id to attach to")
parser.add_argument("-v", "--verbose", action="store_true",
    help="verbose mode: print the BPF program (for debugging purposes)")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="report times in milliseconds (default is microseconds)")
parser.add_argument("-M", "--minimum", type=int, default=0,
    help="display only GCs longer than this many milliseconds")
parser.add_argument("-F", "--filter", type=str,
    help="display only GCs whose description contains this text")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

usdt = USDT(pid=args.pid)

program = """
struct gc_event_t {
    u64 probe_index;
    u64 elapsed_ns;
    u64 field1;
    u64 field2;
    u64 field3;
    u64 field4;
    char string1[32];
    char string2[32];
};
struct entry_t {
    u64 start_ns;
    u64 field1;
    u64 field2;
};

BPF_PERF_OUTPUT(gcs);
BPF_HASH(entry, u64, struct entry_t);
"""

class Probe(object):
    def __init__(self, begin, end, begin_save, end_save, formatter):
        self.begin = begin
        self.end = end
        self.begin_save = begin_save
        self.end_save = end_save
        self.formatter = formatter

    def generate(self):
        text = """
int trace_%s(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    struct entry_t e = {};
    e.start_ns = bpf_ktime_get_ns();
    %s
    entry.update(&pid, &e);
    return 0;
}
int trace_%s(struct pt_regs *ctx) {
    u64 elapsed;
    struct entry_t *e;
    struct gc_event_t event = {};
    u64 pid = bpf_get_current_pid_tgid();
    e = entry.lookup(&pid);
    if (!e) {
        return 0;   // missed the entry event on this thread
    }
    elapsed = bpf_ktime_get_ns() - e->start_ns;
    if (elapsed < %d) {
        return 0;
    }
    event.elapsed_ns = elapsed;
    %s
    gcs.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
        """ % (self.begin, self.begin_save, self.end,
               args.minimum * 1000000, self.end_save)
        return text

    def attach(self):
        usdt.enable_probe_or_bail(self.begin, "trace_%s" % self.begin)
        usdt.enable_probe_or_bail(self.end, "trace_%s" % self.end)

    def format(self, data):
        return self.formatter(data)

probes = []

language = args.language
if not language:
    language = utils.detect_language(languages, args.pid)

#
# Java
#
if language == "java":
    # Oddly, the gc__begin/gc__end probes don't really have any useful
    # information, while the mem__pool* ones do. There's also a bunch of
    # probes described in the hotspot_gc*.stp file which aren't there
    # when looking at a live Java process.
    begin_save = """
    bpf_usdt_readarg(6, ctx, &e.field1);    // used bytes
    bpf_usdt_readarg(8, ctx, &e.field2);    // max bytes
    """
    end_save = """
    event.field1 = e->field1;                  // used bytes at start
    event.field2 = e->field2;                  // max bytes at start
    bpf_usdt_readarg(6, ctx, &event.field3);   // used bytes at end
    bpf_usdt_readarg(8, ctx, &event.field4);   // max bytes at end
    u64 manager = 0, pool = 0;
    bpf_usdt_readarg(1, ctx, &manager);        // ptr to manager name
    bpf_usdt_readarg(3, ctx, &pool);           // ptr to pool name
    bpf_probe_read(&event.string1, sizeof(event.string1), (void *)manager);
    bpf_probe_read(&event.string2, sizeof(event.string2), (void *)pool);
    """

    def formatter(e):
        "%s %s used=%d->%d max=%d->%d" % \
            (e.string1, e.string2, e.field1, e.field3, e.field2, e.field4)
    probes.append(Probe("mem__pool__gc__begin", "mem__pool__gc__end",
                        begin_save, end_save, formatter))
    probes.append(Probe("gc__begin", "gc__end",
                        "", "", lambda _: "no additional info available"))
#
# Node
#
elif language == "node":
    end_save = """
    u32 gc_type = 0;
    bpf_usdt_readarg(1, ctx, &gc_type);
    event.field1 = gc_type;
    """
    descs = {"GC scavenge": 1, "GC mark-sweep-compact": 2,
             "GC incremental mark": 4, "GC weak callbacks": 8}
    probes.append(Probe("gc__start", "gc__done", "", end_save,
                  lambda e: str.join(", ",
                                     [desc for desc, val in descs.items()
                                      if e.field1 & val != 0])))
#
# Python
#
elif language == "python":
    begin_save = """
    int gen = 0;
    bpf_usdt_readarg(1, ctx, &gen);
    e.field1 = gen;
    """
    end_save = """
    long objs = 0;
    bpf_usdt_readarg(1, ctx, &objs);
    event.field1 = e->field1;
    event.field2 = objs;
    """

    def formatter(event):
        "gen %d GC collected %d objects" % \
            (event.field1, event.field2)
    probes.append(Probe("gc__start", "gc__done",
                        begin_save, end_save, formatter))
#
# Ruby
#
elif language == "ruby":
    # Ruby GC probes do not have any additional information available.
    probes.append(Probe("gc__mark__begin", "gc__mark__end",
                        "", "", lambda _: "GC mark stage"))
    probes.append(Probe("gc__sweep__begin", "gc__sweep__end",
                        "", "", lambda _: "GC sweep stage"))

else:
    print("No language detected; use -l to trace a language.")
    exit(1)


for probe in probes:
    program += probe.generate()
    probe.attach()

if args.ebpf or args.verbose:
    if args.verbose:
        print(usdt.get_text())
    print(program)
    if args.ebpf:
        exit()

bpf = BPF(text=program, usdt_contexts=[usdt])
print("Tracing garbage collections in %s process %d... Ctrl-C to quit." %
      (language, args.pid))
time_col = "TIME (ms)" if args.milliseconds else "TIME (us)"
print("%-8s %-8s %-40s" % ("START", time_col, "DESCRIPTION"))

class GCEvent(ct.Structure):
    _fields_ = [
        ("probe_index", ct.c_ulonglong),
        ("elapsed_ns", ct.c_ulonglong),
        ("field1", ct.c_ulonglong),
        ("field2", ct.c_ulonglong),
        ("field3", ct.c_ulonglong),
        ("field4", ct.c_ulonglong),
        ("string1", ct.c_char * 32),
        ("string2", ct.c_char * 32)
        ]

start_ts = time.time()

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(GCEvent)).contents
    elapsed = event.elapsed_ns / 1000000 if args.milliseconds else \
              event.elapsed_ns / 1000
    description = probes[event.probe_index].format(event)
    if args.filter and args.filter not in description:
        return
    print("%-8.3f %-8.2f %s" % (time.time() - start_ts, elapsed, description))

bpf["gcs"].open_perf_buffer(print_event)
while 1:
    bpf.perf_buffer_poll()

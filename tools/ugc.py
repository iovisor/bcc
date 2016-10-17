#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# ugc  Summarize garbage collection events in high-level languages.
#      For Linux, uses BCC, eBPF.
#
# USAGE: ugc {java,python,ruby} PID [-v] [-m]
#
# Copyright 2016 Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 19-Oct-2016   Sasha Goldshtein   Created this.

from __future__ import print_function
import argparse
from bcc import BPF, USDT
import ctypes as ct
import time

examples = """examples:
    ./ugc java 185           # trace Java GCs in process 185
    ./ugc ruby 1344 -m       # trace Ruby GCs reporting in ms
"""
parser = argparse.ArgumentParser(
    description="Summarize garbage collection events in high-level languages.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("language", choices=["java", "python", "ruby"],
    help="language to trace")
parser.add_argument("pid", type=int, help="process id to attach to")
parser.add_argument("-v", "--verbose", action="store_true",
    help="verbose mode: print the BPF program (for debugging purposes)")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="report times in milliseconds (default is microseconds)")
args = parser.parse_args()

usdt = USDT(pid=args.pid)

program = """
struct gc_event_t {
    u64 elapsed_ns;
    char description[80];
};

BPF_PERF_OUTPUT(gcs);
BPF_HASH(entry, u64, u64);  // pid to start timestamp
"""

class Probe(object):
    def __init__(self, begin, end, description):
        self.begin = begin
        self.end = end
        self.description = description

    def generate(self):
        text = """
int trace_%s(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 timestamp = bpf_ktime_get_ns();
    entry.update(&pid, &timestamp);
    return 0;
}
int trace_%s(struct pt_regs *ctx) {
    u64 *start, elapsed;
    char description[] = "%s";
    struct gc_event_t event = {};
    u64 pid = bpf_get_current_pid_tgid();
    start = entry.lookup(&pid);
    if (!start) {
        return 0;   // missed the entry event on this thread
    }
    elapsed = bpf_ktime_get_ns() - *start;
    __builtin_memcpy(&event.description, description, sizeof(description));
    event.elapsed_ns = elapsed;
    gcs.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
        """ % (self.begin, self.end, self.description)
        return text

    def attach(self):
        usdt.enable_probe(self.begin, "trace_%s" % self.begin)
        usdt.enable_probe(self.end, "trace_%s" % self.end)

probes = []

if args.language == "java":
    # TODO Extract additional info like mark/sweep/compact/generation etc.
    #      Oddly, the gc__begin/gc__end probes don't really have any useful
    #      information, while the mem__pool* ones do. There's also a bunch of
    #      probes described in the hotspot_gc*.stp file which aren't there
    #      when looking at a live Java process.
    probes.append(Probe("mem__pool__gc__begin", "mem__pool__gc__end", "TODO"))
    probes.append(Probe("gc__begin", "gc__end", "TODO"))
elif args.language == "python":
    # TODO In gc__start, arg1 is the generation to collect. In gc__end,
    #      arg1 is the number of collected objects.
    probes.append(Probe("gc__start", "gc__done", "GC"))
elif args.language == "ruby":
    # Ruby GC probes do not have any additional information available.
    probes.append(Probe("gc__mark__begin", "gc__mark__end", "mark"))
    probes.append(Probe("gc__sweep__begin", "gc__sweep__end", "sweep"))

for probe in probes:
    program += probe.generate()
    probe.attach()

if args.verbose:
    print(usdt.get_text())
    print(program)

bpf = BPF(text=program, usdt_contexts=[usdt])
print("Tracing garbage collections in %s process %d... Ctrl-C to quit." %
      (args.language, args.pid))
time_col = "TIME (ms)" if args.milliseconds else "TIME (us)"
print("%-8s %-30s %-8s" % ("START", "DESCRIPTION", time_col))

class Data(ct.Structure):
    _fields_ = [
        ("elapsed_ns", ct.c_ulonglong),
        ("description", ct.c_char * 80)
        ]

start_ts = time.time()

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    elapsed = event.elapsed_ns/1000000 if args.milliseconds else \
              event.elapsed_ns/1000
    print("%-8.3f %-30s %-8.2f" % (time.time() - start_ts,
                                   event.description, elapsed))

bpf["gcs"].open_perf_buffer(print_event)
while 1:
    bpf.kprobe_poll()

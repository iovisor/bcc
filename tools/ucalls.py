#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# ucalls  Summarize method calls in high-level languages.
#         For Linux, uses BCC, eBPF.
#
# USAGE: ucalls {java,python,ruby} PID [interval] [-T TOP] [-L] [-v] [-m]
#
# Copyright 2016 Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 19-Oct-2016   Sasha Goldshtein   Created this.

# TODO Add node!
# TODO Add shell wrappers: javacalls, pythoncalls, etc.
# TODO Add syscalls information from sys_* and SyS_* kprobes

from __future__ import print_function
import argparse
from bcc import BPF, USDT
from time import sleep

examples = """examples:
    ./ucalls java 185           # trace Java calls and print statistics on ^C
    ./ucalls python 2020 1      # trace Python calls and print every second
    ./ucalls ruby 1344 -T 10    # trace top 10 Ruby method calls
    ./ucalls ruby 1344 -L       # trace Ruby calls including latency
    ./ucalls python 2020 -mL    # trace Python calls including latency in ms
"""
parser = argparse.ArgumentParser(
    description="Summarize method calls in high-level languages.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("language", choices=["java", "python", "ruby"],
    help="language to trace")
parser.add_argument("pid", type=int, help="process id to attach to")
parser.add_argument("interval", type=int, nargs='?',
    help="print every specified number of seconds")
parser.add_argument("-T", "--top", type=int,
    help="number of most frequent/slow calls to print")
parser.add_argument("-L", "--latency", action="store_true",
    help="record method latency from enter to exit (except recursive calls)")
parser.add_argument("-v", "--verbose", action="store_true",
    help="verbose mode: print the BPF program (for debugging purposes)")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="report times in milliseconds (default is microseconds)")
args = parser.parse_args()

# We assume that the entry and return probes have the same arguments. This is
# the case for Java, Python, and Ruby. If there's a language where it's not the
# case, we will need to build a custom correlator from entry to exit.
if args.language == "java":
    # TODO for JVM entries, we actually have the real length of the class
    #      and method strings in arg3 and arg5 respectively...
    entry_probe = "method__entry"
    return_probe = "method__return"
    read_class = "bpf_usdt_readarg(2, ctx, &clazz);"
    read_method = "bpf_usdt_readarg(4, ctx, &method);"
elif args.language == "python":
    entry_probe = "function__entry"
    return_probe = "function__return"
    read_class = "bpf_usdt_readarg(1, ctx, &clazz);"    # filename really
    read_method = "bpf_usdt_readarg(2, ctx, &method);"
elif args.language == "ruby":
    entry_probe = "method__entry"
    return_probe = "method__return"
    read_class = "bpf_usdt_readarg(1, ctx, &clazz);"
    read_method = "bpf_usdt_readarg(2, ctx, &method);"

# TODO The whole string reading here reads beyond the null terminator, which
#      might lead to problems if we consider past the end of the string as
#      part of the class or method name. Think what to do with this.
program = """
#define MAX_STRING_LENGTH 80
DEFINE_LATENCY

struct method_t {
    char clazz[MAX_STRING_LENGTH];
    char method[MAX_STRING_LENGTH];
};
struct entry_t {
    u64 pid;
    struct method_t method;
};
struct info_t {
    u64 num_calls;
    u64 total_ns;
};

#ifndef LATENCY
BPF_HASH(counts, struct method_t, u64); // number of calls
#else
BPF_HASH(times, struct method_t, struct info_t);
BPF_HASH(entry, struct entry_t, u64);   // timestamp at entry
#endif

int trace_entry(struct pt_regs *ctx) {
    u64 clazz = 0, method = 0, val = 0;
    u64 *valp;
    struct entry_t data = {0};
#ifdef LATENCY
    u64 timestamp = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
#endif
    READ_CLASS
    READ_METHOD
    bpf_probe_read(&data.method.clazz, sizeof(data.method.clazz),
                   (void *)clazz);
    bpf_probe_read(&data.method.method, sizeof(data.method.method),
                   (void *)method);
#ifndef LATENCY
    valp = counts.lookup_or_init(&data.method, &val);
    ++(*valp);
#endif
#ifdef LATENCY
    entry.update(&data, &timestamp);
#endif
    return 0;
}

#ifdef LATENCY
int trace_return(struct pt_regs *ctx) {
    u64 *entry_timestamp, clazz = 0, method = 0;
    struct info_t *info, zero = {};
    struct entry_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    READ_CLASS
    READ_METHOD
    bpf_probe_read(&data.method.clazz, sizeof(data.method.clazz),
                   (void *)clazz);
    bpf_probe_read(&data.method.method, sizeof(data.method.method),
                   (void *)method);
    entry_timestamp = entry.lookup(&data);
    if (!entry_timestamp) {
        return 0;   // missed the entry event
    }
    info = times.lookup_or_init(&data.method, &zero);
    info->num_calls += 1;
    info->total_ns += bpf_ktime_get_ns() - *entry_timestamp;
    entry.delete(&data);
    return 0;
}
#endif
""".replace("READ_CLASS", read_class) \
   .replace("READ_METHOD", read_method) \
   .replace("DEFINE_LATENCY", "#define LATENCY" if args.latency else "")
usdt = USDT(pid=args.pid)
usdt.enable_probe(entry_probe, "trace_entry")
if args.latency:
    usdt.enable_probe(return_probe, "trace_return")

if args.verbose:
    print(usdt.get_text())
    print(program)

bpf = BPF(text=program, usdt_contexts=[usdt])
print("Tracing method calls in %s process %d... Ctrl-C to quit." %
      (args.language, args.pid))
while True:
    try:
        sleep(args.interval or 99999999)
    except KeyboardInterrupt:
        pass
    print()
    if args.latency:
        data = bpf["times"]
        data = sorted(data.items(), key=lambda (k, v): v.total_ns)
        time_col = "TIME (ms)" if args.milliseconds else "TIME (us)"
        print("%-50s %8s %8s" % ("METHOD", "# CALLS", time_col))
    else:
        data = bpf["counts"]
        data = sorted(data.items(), key=lambda (k, v): v.value)
        print("%-50s %8s" % ("METHOD", "# CALLS"))
    if args.top:
        data = data[-args.top:]
    for key, value in data:
        if args.latency:
            time = value.total_ns/1000000.0 if args.milliseconds else \
                   value.total_ns/1000.0
            print("%-50s %8d %6.2f" % (key.clazz + "." + key.method,
                                       value.num_calls, time))
        else:
            print("%-50s %8d" % (key.clazz + "." + key.method, value.value))
    if not args.interval:
        exit()

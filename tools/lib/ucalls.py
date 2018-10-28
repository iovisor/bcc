#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# ucalls  Summarize method calls in high-level languages and/or system calls.
#         For Linux, uses BCC, eBPF.
#
# USAGE: ucalls [-l {java,perl,php,python,ruby,tcl}] [-h] [-T TOP] [-L] [-S] [-v] [-m]
#        pid [interval]
#
# Copyright 2016 Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 19-Oct-2016   Sasha Goldshtein   Created this.

from __future__ import print_function
import argparse
from bcc import BPF, USDT, utils
from time import sleep
import os

languages = ["java", "perl", "php", "python", "ruby", "tcl"]

examples = """examples:
    ./ucalls -l java 185        # trace Java calls and print statistics on ^C
    ./ucalls -l python 2020 1   # trace Python calls and print every second
    ./ucalls -l java 185 -S     # trace Java calls and syscalls
    ./ucalls 6712 -S            # trace only syscall counts
    ./ucalls -l ruby 1344 -T 10 # trace top 10 Ruby method calls
    ./ucalls -l ruby 1344 -L    # trace Ruby calls including latency
    ./ucalls -l php 443 -LS     # trace PHP calls and syscalls with latency
    ./ucalls -l python 2020 -mL # trace Python calls including latency in ms
"""
parser = argparse.ArgumentParser(
    description="Summarize method calls in high-level languages.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("pid", type=int, help="process id to attach to")
parser.add_argument("interval", type=int, nargs='?',
    help="print every specified number of seconds")
parser.add_argument("-l", "--language", choices=languages + ["none"],
    help="language to trace (if none, trace syscalls only)")
parser.add_argument("-T", "--top", type=int,
    help="number of most frequent/slow calls to print")
parser.add_argument("-L", "--latency", action="store_true",
    help="record method latency from enter to exit (except recursive calls)")
parser.add_argument("-S", "--syscalls", action="store_true",
    help="record syscall latency (adds overhead)")
parser.add_argument("-v", "--verbose", action="store_true",
    help="verbose mode: print the BPF program (for debugging purposes)")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="report times in milliseconds (default is microseconds)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

language = args.language
if not language:
    language = utils.detect_language(languages, args.pid)

# We assume that the entry and return probes have the same arguments. This is
# the case for Java, Python, Ruby, and PHP. If there's a language where it's
# not the case, we will need to build a custom correlator from entry to exit.
extra_message = ""
if language == "java":
    # TODO for JVM entries, we actually have the real length of the class
    #      and method strings in arg3 and arg5 respectively, so we can insert
    #      the null terminator in its proper position.
    entry_probe = "method__entry"
    return_probe = "method__return"
    read_class = "bpf_usdt_readarg(2, ctx, &clazz);"
    read_method = "bpf_usdt_readarg(4, ctx, &method);"
    extra_message = ("If you do not see any results, make sure you ran java"
                     " with option -XX:+ExtendedDTraceProbes")
elif language == "perl":
    entry_probe = "sub__entry"
    return_probe = "sub__return"
    read_class = "bpf_usdt_readarg(2, ctx, &clazz);"    # filename really
    read_method = "bpf_usdt_readarg(1, ctx, &method);"
elif language == "php":
    entry_probe = "function__entry"
    return_probe = "function__return"
    read_class = "bpf_usdt_readarg(4, ctx, &clazz);"
    read_method = "bpf_usdt_readarg(1, ctx, &method);"
    extra_message = ("If you do not see any results, make sure the environment"
                     " variable USE_ZEND_DTRACE is set to 1")
elif language == "python":
    entry_probe = "function__entry"
    return_probe = "function__return"
    read_class = "bpf_usdt_readarg(1, ctx, &clazz);"    # filename really
    read_method = "bpf_usdt_readarg(2, ctx, &method);"
elif language == "ruby":
    # TODO Also probe cmethod__entry and cmethod__return with same arguments
    entry_probe = "method__entry"
    return_probe = "method__return"
    read_class = "bpf_usdt_readarg(1, ctx, &clazz);"
    read_method = "bpf_usdt_readarg(2, ctx, &method);"
elif language == "tcl":
    # TODO Also consider probe cmd__entry and cmd__return with same arguments
    entry_probe = "proc__entry"
    return_probe = "proc__return"
    read_class = ""  # no class/file info available
    read_method = "bpf_usdt_readarg(1, ctx, &method);"
elif not language or language == "none":
    if not args.syscalls:
        print("Nothing to do; use -S to trace syscalls.")
        exit(1)
    entry_probe, return_probe, read_class, read_method = ("", "", "", "")
    if language:
        language = None

program = """
#include <linux/ptrace.h>

#define MAX_STRING_LENGTH 80
DEFINE_NOLANG
DEFINE_LATENCY
DEFINE_SYSCALLS

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
struct syscall_entry_t {
    u64 timestamp;
    u64 ip;
};

#ifndef LATENCY
  BPF_HASH(counts, struct method_t, u64);            // number of calls
  #ifdef SYSCALLS
    BPF_HASH(syscounts, u64, u64);                   // number of calls per IP
  #endif  // SYSCALLS
#else
  BPF_HASH(times, struct method_t, struct info_t);
  BPF_HASH(entry, struct entry_t, u64);              // timestamp at entry
  #ifdef SYSCALLS
    BPF_HASH(systimes, u64, struct info_t);          // latency per IP
    BPF_HASH(sysentry, u64, struct syscall_entry_t); // ts + IP at entry
  #endif  // SYSCALLS
#endif

#ifndef NOLANG
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
#endif  // LATENCY
#endif  // NOLANG

#ifdef SYSCALLS
int syscall_entry(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 *valp, ip = PT_REGS_IP(ctx), val = 0;
    PID_FILTER
#ifdef LATENCY
    struct syscall_entry_t data = {};
    data.timestamp = bpf_ktime_get_ns();
    data.ip = ip;
#endif
#ifndef LATENCY
    valp = syscounts.lookup_or_init(&ip, &val);
    ++(*valp);
#endif
#ifdef LATENCY
    sysentry.update(&pid, &data);
#endif
    return 0;
}

#ifdef LATENCY
int syscall_return(struct pt_regs *ctx) {
    struct syscall_entry_t *e;
    struct info_t *info, zero = {};
    u64 pid = bpf_get_current_pid_tgid(), ip;
    PID_FILTER
    e = sysentry.lookup(&pid);
    if (!e) {
        return 0;   // missed the entry event
    }
    ip = e->ip;
    info = systimes.lookup_or_init(&ip, &zero);
    info->num_calls += 1;
    info->total_ns += bpf_ktime_get_ns() - e->timestamp;
    sysentry.delete(&pid);
    return 0;
}
#endif  // LATENCY
#endif  // SYSCALLS
""".replace("READ_CLASS", read_class) \
   .replace("READ_METHOD", read_method) \
   .replace("PID_FILTER", "if ((pid >> 32) != %d) { return 0; }" % args.pid) \
   .replace("DEFINE_NOLANG", "#define NOLANG" if not language else "") \
   .replace("DEFINE_LATENCY", "#define LATENCY" if args.latency else "") \
   .replace("DEFINE_SYSCALLS", "#define SYSCALLS" if args.syscalls else "")

if language:
    usdt = USDT(pid=args.pid)
    usdt.enable_probe_or_bail(entry_probe, "trace_entry")
    if args.latency:
        usdt.enable_probe_or_bail(return_probe, "trace_return")
else:
    usdt = None

if args.ebpf or args.verbose:
    if args.verbose and usdt:
        print(usdt.get_text())
    print(program)
    if args.ebpf:
        exit()

bpf = BPF(text=program, usdt_contexts=[usdt] if usdt else [])
if args.syscalls:
    syscall_regex = "^[Ss]y[Ss]_.*"
    bpf.attach_kprobe(event_re=syscall_regex, fn_name="syscall_entry")
    if args.latency:
        bpf.attach_kretprobe(event_re=syscall_regex, fn_name="syscall_return")
    print("Attached %d kernel probes for syscall tracing." %
          bpf.num_open_kprobes())

def get_data():
    # Will be empty when no language was specified for tracing
    if args.latency:
        data = list(map(lambda kv: (kv[0].clazz.decode('utf-8', 'replace') \
                                    + "." + \
                                    kv[0].method.decode('utf-8', 'replace'),
                                   (kv[1].num_calls, kv[1].total_ns)),
                   bpf["times"].items()))
    else:
        data = list(map(lambda kv: (kv[0].clazz.decode('utf-8', 'replace') \
                                    + "." + \
                                    kv[0].method.decode('utf-8', 'replace'),
                                   (kv[1].value, 0)),
                   bpf["counts"].items()))

    if args.syscalls:
        if args.latency:
            syscalls = map(lambda kv: (bpf.ksym(kv[0].value),
                                           (kv[1].num_calls, kv[1].total_ns)),
                           bpf["systimes"].items())
            data.extend(syscalls)
        else:
            syscalls = map(lambda kv: (bpf.ksym(kv[0].value),
                                       (kv[1].value, 0)),
                           bpf["syscounts"].items())
            data.extend(syscalls)

    return sorted(data, key=lambda kv: kv[1][1 if args.latency else 0])

def clear_data():
    if args.latency:
        bpf["times"].clear()
    else:
        bpf["counts"].clear()

    if args.syscalls:
        if args.latency:
            bpf["systimes"].clear()
        else:
            bpf["syscounts"].clear()

exit_signaled = False
print("Tracing calls in process %d (language: %s)... Ctrl-C to quit." %
      (args.pid, language or "none"))
if extra_message:
    print(extra_message)
while True:
    try:
        sleep(args.interval or 99999999)
    except KeyboardInterrupt:
        exit_signaled = True
    print()
    data = get_data()   # [(function, (num calls, latency in ns))]
    if args.latency:
        time_col = "TIME (ms)" if args.milliseconds else "TIME (us)"
        print("%-50s %8s %8s" % ("METHOD", "# CALLS", time_col))
    else:
        print("%-50s %8s" % ("METHOD", "# CALLS"))
    if args.top:
        data = data[-args.top:]
    for key, value in data:
        if args.latency:
            time = value[1] / 1000000.0 if args.milliseconds else \
                   value[1] / 1000.0
            print("%-50s %8d %6.2f" % (key, value[0], time))
        else:
            print("%-50s %8d" % (key, value[0]))
    if args.interval and not exit_signaled:
        clear_data()
    else:
        if args.syscalls:
            print("Detaching kernel probes, please wait...")
        exit()

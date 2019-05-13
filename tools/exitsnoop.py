#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
from __future__ import print_function
#
# exitsnoop Trace all process termination (exit, fatal signal)
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: sudo exitsnoop [-h] [-xf] [-t] [-p PID]
#
examples = """examples:
    sudo exitsnoop           # trace all process termination
    sudo exitsnoop -x        # trace only fails, exclude exit(0)
    sudo exitsnoop -t        # include timestamps
    sudo exitsnoop -p 181    # only trace PID 181
"""
"""
  Exit status (from <include/sysexits.h>):

    0 EX_OK        Success
    2              argparse error
   70 EX_SOFTWARE  syntax error detected by compiler, or
                   verifier error from kernel
   77 EX_NOPERM    Need sudo (CAP_SYS_ADMIN) for BPF() system call

  The template for this script was Brendan Gregg's execsnoop
      https://github.com/iovisor/bcc/blob/master/tools/execsnoop.py

  More information about this script is in bcc/tools/exitsnoop_example.txt

  Copyright 2016 Netflix, Inc.
  Copyright 2019 Instana, Inc.
  Licensed under the Apache License, Version 2.0 (the "License")

  07-Feb-2016   Brendan Gregg              Created execsnoop
  13-May-2019   Arturo Martin-de-Nicolas   Created exitsnoop
"""

import argparse
from bcc import BPF
from time import strftime
import ctypes as ct
import os
import sys

# =============================
# parse arguments
# =============================
parser = argparse.ArgumentParser(
    description="Trace all process termination (exit, fatal signal)",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

a = parser.add_argument
a("-t", "--timestamp", action="store_true", help="include timestamp on output")
a("-p", "--pid",                            help="trace this PID only")
a(      "--ebpf",      action="store_true", help=argparse.SUPPRESS)
a("-x", "--failed",    action="store_true", help="trace fails, exclude exit(0)")

args = parser.parse_args()

# =============================
# BPF Embedded C for sched_process_exit
# =============================
TASK_COMM_LEN = 16      # linux/sched.h

class Data(ct.Structure):
    _pack_ = 1
    _fields_ = [
        ("ts", ct.c_ulonglong),
        ("pid", ct.c_uint), # task->tgid, thread group id == sys_getpid()
        ("ppid", ct.c_uint),# task->parent->tgid, notified of exit
        ("exit_code", ct.c_int),
        ("sig_info", ct.c_uint),
        ("task", ct.c_char * TASK_COMM_LEN)
    ]

embedded_c = """
#include <linux/sched.h>
BPF_STATIC_ASSERT_DEF

struct data_t {
    u64 ts;
    u32 pid;
    u32 ppid;
    int exit_code;
    u32 sig_info;
    char task[TASK_COMM_LEN];
} __attribute__((packed));

BPF_STATIC_ASSERT(sizeof(struct data_t) == CTYPES_SIZEOF_DATA);

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(sched, sched_process_exit)
{
    struct task_struct *task = (typeof(task))bpf_get_current_task();
    if (FILTER_PID || FILTER_EXIT_CODE) { return 0; }

    struct data_t data = {
          .ts = bpf_ktime_get_ns(),
          .pid = task->tgid,
          .ppid = task->parent->tgid,
          .exit_code = task->exit_code >> 8,
          .sig_info = task->exit_code & 0xFF,
    };
    bpf_get_current_comm(&data.task, sizeof(data.task));

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

# =============================
# code substitutions
# =============================
# TODO: this macro belongs in bcc/src/cc/export/helpers.h
bpf_static_assert_def = """
#ifndef BPF_STATIC_ASSERT
#define BPF_STATIC_ASSERT(condition) __attribute__((unused)) \\
    extern int bpf_static_assert[(condition) ? 1 : -1]
#endif
"""
code_substitutions = [
    ("BPF_STATIC_ASSERT_DEF", bpf_static_assert_def),
    ("CTYPES_SIZEOF_DATA", str(ct.sizeof(Data))),
    ("FILTER_PID", "0" if not args.pid else "(task->tgid != %s)" % args.pid),
    ("FILTER_EXIT_CODE", "0" if not args.failed else "(task->exit_code == 0)"),
]
for old,new in code_substitutions:
    embedded_c = embedded_c.replace(old, new)

if args.ebpf:
    print(embedded_c)
    sys.exit()

# =============================
# print header and events
# =============================
def print_header():
    if args.timestamp:
        print("%-18s" % ("TIME(s)"), end="")
    print("%-16s %-6s %-6s %-10s" % ("COMM", "PID", "PPID", "EXIT_CODE"))

def print_event(cpu, data, size): # callback
    global start_ts
    e = ct.cast(data, ct.POINTER(Data)).contents
    if args.timestamp:
        if start_ts == 0:
            start_ts = e.ts
        print("%-8s %-8.3f " % (strftime("%H:%M:%S"),
                                    float(e.ts - start_ts) / 1000000), end="")
    print("%-16s %-6d %-6d " % (e.task.decode(), e.pid, e.ppid), end="")
    if e.sig_info == 0:
        print("0" if e.exit_code == 0 else "FAIL: exit_code=%d" % e.exit_code)
    else:
        if e.sig_info & 0x7F:
            print("KILL: signal=%d" % (e.sig_info & 0x7F), end="")
        if e.sig_info & 0x80:
            print(", core dumped ", end="")
        print()

# =============================
# initialize BPF
# =============================
def error_exit(code, reason):
    print(reason)
    sys.exit(code)

if os.geteuid() != 0:
    error_exit(os.EX_NOPERM, "Need sudo (CAP_SYS_ADMIN) for BPF() system call")

try:
    b = BPF(text=embedded_c)
except Exception as e:
    error_exit(os.EX_SOFTWARE, "BPF error: %s" % e)
except:
    error_exit(os.EX_SOFTWARE, "Unknown error: %s" % sys.exc_info()[0])

start_ts = 0

# =============================
# poll for events with callback
# print_event until Ctrl-C pressed
# =============================
print_header()
b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
        if args.pid:
            sys.exit()
    except KeyboardInterrupt:
        print()
        sys.exit()

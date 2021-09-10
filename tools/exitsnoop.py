#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
from __future__ import print_function

import argparse
import ctypes as ct
import os
import platform
import re
import signal
import sys

from bcc import BPF
from datetime import datetime
from time import strftime

#
# exitsnoop Trace all process termination (exit, fatal signal)
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: exitsnoop [-h] [-x] [-t] [--utc] [--label[=LABEL]] [-p PID]
#
_examples = """examples:
    exitsnoop                # trace all process termination
    exitsnoop -x             # trace only fails, exclude exit(0)
    exitsnoop -t             # include timestamps (local time)
    exitsnoop --utc          # include timestamps (UTC)
    exitsnoop -p 181         # only trace PID 181
    exitsnoop --label=exit   # label each output line with 'exit'
    exitsnoop --per-thread   # trace per thread termination
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

  07-Feb-2016   Brendan Gregg (Netflix)            Created execsnoop
  04-May-2019   Arturo Martin-de-Nicolas (Instana) Created exitsnoop
  13-May-2019   Jeroen Soeters (Instana) Refactor to import as module
"""

def _getParser():
    parser = argparse.ArgumentParser(
        description="Trace all process termination (exit, fatal signal)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_examples)
    a=parser.add_argument
    a("-t", "--timestamp", action="store_true", help="include timestamp (local time default)")
    a("--utc",             action="store_true", help="include timestamp in UTC (-t implied)")
    a("-p", "--pid",                            help="trace this PID only")
    a("--label",                                help="label each line")
    a("-x", "--failed",    action="store_true", help="trace only fails, exclude exit(0)")
    a("--per-thread",      action="store_true", help="trace per thread termination")
    # print the embedded C program and exit, for debugging
    a("--ebpf",            action="store_true", help=argparse.SUPPRESS)
    # RHEL 7.6 keeps task->start_time as struct timespec, convert to u64 nanoseconds
    a("--timespec",        action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args


class Global():
    parse_args = _getParser()
    args = None
    argv = None
    SIGNUM_TO_SIGNAME = dict((v, re.sub("^SIG", "", k))
        for k,v in signal.__dict__.items() if re.match("^SIG[A-Z]+$", k))


class Data(ct.Structure):
    """Event data matching struct data_t in _embedded_c()."""
    _TASK_COMM_LEN = 16      # linux/sched.h
    _pack_ = 1
    _fields_ = [
        ("start_time", ct.c_ulonglong), # task->start_time, see --timespec arg
        ("exit_time", ct.c_ulonglong),  # bpf_ktime_get_ns()
        ("pid", ct.c_uint), # task->tgid, thread group id == sys_getpid()
        ("tid", ct.c_uint), # task->pid, thread id == sys_gettid()
        ("ppid", ct.c_uint),# task->parent->tgid, notified of exit
        ("exit_code", ct.c_int),
        ("sig_info", ct.c_uint),
        ("task", ct.c_char * _TASK_COMM_LEN)
    ]

def _embedded_c(args):
    """Generate C program for sched_process_exit tracepoint in kernel/exit.c."""
    c = """
    EBPF_COMMENT
    #include <linux/sched.h>
    BPF_STATIC_ASSERT_DEF

    struct data_t {
        u64 start_time;
        u64 exit_time;
        u32 pid;
        u32 tid;
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
            .start_time = PROCESS_START_TIME_NS,
            .exit_time = bpf_ktime_get_ns(),
            .pid = task->tgid,
            .tid = task->pid,
            .ppid = task->parent->tgid,
            .exit_code = task->exit_code >> 8,
            .sig_info = task->exit_code & 0xFF,
        };
        bpf_get_current_comm(&data.task, sizeof(data.task));

        events.perf_submit(args, &data, sizeof(data));
        return 0;
    }
    """
    # TODO: this macro belongs in bcc/src/cc/export/helpers.h
    bpf_static_assert_def = r"""
    #ifndef BPF_STATIC_ASSERT
    #define BPF_STATIC_ASSERT(condition) __attribute__((unused)) \
    extern int bpf_static_assert[(condition) ? 1 : -1]
    #endif
    """

    if Global.args.pid:
        if Global.args.per_thread:
            filter_pid = "task->tgid != %s" % Global.args.pid
        else:
            filter_pid = "!(task->tgid == %s && task->pid == task->tgid)" % Global.args.pid
    else:
        filter_pid = '0' if Global.args.per_thread else 'task->pid != task->tgid'

    code_substitutions = [
        ('EBPF_COMMENT', '' if not Global.args.ebpf else _ebpf_comment()),
        ("BPF_STATIC_ASSERT_DEF", bpf_static_assert_def),
        ("CTYPES_SIZEOF_DATA", str(ct.sizeof(Data))),
        ('FILTER_PID', filter_pid),
        ('FILTER_EXIT_CODE', '0' if not Global.args.failed else 'task->exit_code == 0'),
        ('PROCESS_START_TIME_NS', 'task->start_time' if not Global.args.timespec else
             '(task->start_time.tv_sec * 1000000000L) + task->start_time.tv_nsec'),
    ]
    for old,new in code_substitutions:
        c = c.replace(old, new)
    return c

def _ebpf_comment():
    """Return a C-style comment with information about the generated code."""
    comment=('Created by %s at %s:\n\t%s' %
                    (sys.argv[0], strftime("%Y-%m-%d %H:%M:%S %Z"), _embedded_c.__doc__))
    args = str(vars(Global.args)).replace('{','{\n\t').replace(', ',',\n\t').replace('}',',\n }\n\n')
    return ("\n   /*" + ("\n %s\n\n ARGV = %s\n\n ARGS = %s/" %
                             (comment, ' '.join(Global.argv), args))
                   .replace('\n','\n\t*').replace('\t','    '))

def _print_header():
    if Global.args.timestamp:
        title = 'TIME-' + ('UTC' if Global.args.utc else strftime("%Z"))
        print("%-13s" % title, end="")
    if Global.args.label is not None:
        print("%-6s" % "LABEL", end="")
    print("%-16s %-6s %-6s %-6s %-7s %-10s" %
              ("PCOMM", "PID", "PPID", "TID", "AGE(s)", "EXIT_CODE"))

def _print_event(cpu, data, size): # callback
    """Print the exit event."""
    e = ct.cast(data, ct.POINTER(Data)).contents
    if Global.args.timestamp:
        now = datetime.utcnow() if Global.args.utc else datetime.now()
        print("%-13s" % (now.strftime("%H:%M:%S.%f")[:-3]), end="")
    if Global.args.label is not None:
        label = Global.args.label if len(Global.args.label) else 'exit'
        print("%-6s" % label, end="")
    age = (e.exit_time - e.start_time) / 1e9
    print("%-16s %-6d %-6d %-6d %-7.2f " %
              (e.task.decode(), e.pid, e.ppid, e.tid, age), end="")
    if e.sig_info == 0:
        print("0" if e.exit_code == 0 else "code %d" % e.exit_code)
    else:
        sig = e.sig_info & 0x7F
        if sig:
            print("signal %d (%s)" % (sig, signum_to_signame(sig)), end="")
        if e.sig_info & 0x80:
            print(", core dumped ", end="")
        print()

# =============================
# Module: These functions are available for import
# =============================
def initialize(arg_list = sys.argv[1:]):
    """Trace all process termination.

    arg_list - list of args, if omitted then uses command line args
               arg_list is passed to argparse.ArgumentParser.parse_args()

    For example, if arg_list = [ '-x', '-t' ]
       args.failed == True
       args.timestamp == True

    Returns a tuple (return_code, result)
       0 = Ok, result is the return value from BPF()
       1 = args.ebpf is requested, result is the generated C code
       os.EX_NOPERM: need CAP_SYS_ADMIN, result is error message
       os.EX_SOFTWARE: internal software error, result is error message
    """
    Global.argv = arg_list
    Global.args = Global.parse_args(arg_list)
    if Global.args.utc and not Global.args.timestamp:
        Global.args.timestamp = True
    if not Global.args.ebpf and os.geteuid() != 0:
        return (os.EX_NOPERM, "Need sudo (CAP_SYS_ADMIN) for BPF() system call")
    if re.match('^3\.10\..*el7.*$', platform.release()): # Centos/Red Hat
        Global.args.timespec = True
    for _ in range(2):
        c = _embedded_c(Global.args)
        if Global.args.ebpf:
            return (1, c)
        try:
            return (os.EX_OK, BPF(text=c))
        except Exception as e:
            error = format(e)
            if (not Global.args.timespec
                    and error.find('struct timespec')
                    and error.find('start_time')):
                print('This kernel keeps task->start_time in a struct timespec.\n' +
                          'Retrying with --timespec')
                Global.args.timespec = True
                continue
            return (os.EX_SOFTWARE, "BPF error: " + error)
        except:
            return (os.EX_SOFTWARE, "Unexpected error: {0}".format(sys.exc_info()[0]))

def snoop(bpf, event_handler):
    """Call event_handler for process termination events.

    bpf - result returned by successful initialize()
    event_handler - callback function to handle termination event
    args.pid - Return after event_handler is called, only monitoring this pid
    """
    bpf["events"].open_perf_buffer(event_handler)
    while True:
        bpf.perf_buffer_poll()
        if Global.args.pid:
            return

def signum_to_signame(signum):
    """Return the name of the signal corresponding to signum."""
    return Global.SIGNUM_TO_SIGNAME.get(signum, "unknown")

# =============================
# Script: invoked as a script
# =============================
def main():
    try:
        rc, buffer = initialize()
        if rc:
            print(buffer)
            sys.exit(0 if Global.args.ebpf else rc)
        _print_header()
        snoop(buffer, _print_event)
    except KeyboardInterrupt:
        print()
        sys.exit()

    return 0

if __name__ == '__main__':
    main()

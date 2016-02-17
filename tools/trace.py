#!/usr/bin/env python
#
# trace         Trace a function and print a trace message based on its
#               parameters, with an optional filter.
#
# USAGE: trace [-h] [-p PID] [-v] probe [probe ...]
#
# Licensed under the Apache License, Version 2.0 (the "License")
# Copyright (C) 2016 Sasha Goldshtein.

from bcc import BPF
from time import sleep, strftime
import argparse
import re

class Probe(object):
        probe_count = 0

        def __init__(self, probe):
                self.raw_probe = probe
                self.probe_name = "probe_%d" % Probe.probe_count
                Probe.probe_count += 1
                self._parse_probe()

        def __str__(self):
                return "%s:%s`%s FLT=%s ACT=%s" % (self.probe_type,
                        self.library, self.function, self.filter,
                        self.action)

        def _bail(self, error):
                raise ValueError("error parsing probe %s: %s" %
                                 (self.raw_probe, error))

        def _parse_probe(self):
                text = self.raw_probe

                # Everything until the first space is the probe specifier
                first_space = text.find(' ')
                self._parse_spec(text[:first_space])
                text = text[first_space:].lstrip()

                # If we now have a (, wait for the balanced closing ) and that
                # will be the predicate
                self.filter = None
                if text[0] == "(":
                        balance = 1
                        for i in range(1, len(text)):
                                if text[i] == "(":
                                        balance += 1
                                if text[i] == ")":
                                        balance -= 1
                                if balance == 0:
                                        self._parse_filter(text[1:i])
                                        text = text[i+1:]
                                        break
                        if self.filter is None:
                                self._bail("unmatched end of predicate")

                if self.filter is None:
                        self.filter = "1"

                # The remainder of the text is the printf action
                self._parse_action(text.lstrip())

        def _parse_spec(self, spec):
                parts = spec.split(":")
                if len(parts) == 1:
                        self.probe_type = "p"
                        self._parse_func(parts[0])
                else:
                        self.probe_type = parts[0]
                        self._parse_func(parts[1])

        def _parse_func(self, func):
                parts = func.split("`")
                if len(parts) == 1:
                        self.library = ""
                        self.function = parts[0]
                else:
                        self.library = parts[0]
                        self.function = parts[1]

        def _parse_filter(self, filt):
                self.filter = self._replace_args(filt.strip("(").strip(")"))

        def _parse_action(self, action):
                self.action = self._replace_args(action)

        def _replace_args(self, expr):
                expr = expr.replace("retval", "ctx->ax")
                expr = expr.replace("arg1", "ctx->di")
                expr = expr.replace("arg2", "ctx->si")
                expr = expr.replace("arg3", "ctx->dx")
                expr = expr.replace("arg4", "ctx->cx")
                # TODO More args? Don't replace inside format string?
                return expr

        def generate_program(self, pid):
                self.pid = pid
                if len(self.library) == 0 and pid is not None:
                        pid_filter = """
        u32 __pid = bpf_get_current_pid_tgid();
        if (__pid != %d) { return 0; }
"""             % pid
                else:
                        pid_filter = ""

                text = """
int %s(struct pt_regs *ctx)
{
        %s
        if (!(%s)) return 0;
        bpf_trace_printk(%s);   /* TODO Replace with BPF_PERF    */
        return 0;               /* TODO Add PID, COMM, TIME etc. */
}
"""
                text = text % (self.probe_name, pid_filter,
                               self.filter, self.action)
                return text

        def attach(self, bpf):
                if len(self.library) == 0:
                        self._attach_k(bpf)
                else:
                        self._attach_u(bpf)

        def _attach_k(self, bpf):
                if self.probe_type == "r":
                        bpf.attach_kretprobe(event=self.function,
                                             fn_name=self.probe_name)
                elif self.probe_type == "p":
                        bpf.attach_kprobe(event=self.function,
                                          fn_name=self.probe_name)

        def _attach_u(self, bpf):
                if self.probe_type == "r":
                        bpf.attach_uretprobe(name=self.library,
                                             sym=self.function,
                                             fn_name=self.probe_name,
                                             pid=self.pid)
                else:
                        bpf.attach_uprobe(name=self.library,
                                          sym=self.function,
                                          fn_name=self.probe_name,
                                          pid=self.pid)

examples = """
TODO NEED OBVIOUSLY BETTER EXAMPLES
trace do_sys_open
        Trace the open syscall and print a default trace message when entered
trace 'do_sys_open "%s", arg1'
        Trace the open syscall and print the filename being opened
trace r:do_sys_return
        Trace the return from the open syscall
trace 'do_sys_open (arg2 == 42) "%s %d", arg1, arg2'
        Trace the open syscall only if the flags (arg2) argument is 42
trace 'c`malloc "size = %d", arg1'
        Trace malloc calls and print the size being allocated
trace 'r:c`malloc (retval) "allocated = %p", retval
        Trace returns from malloc and print non-NULL allocated buffers
"""

parser = argparse.ArgumentParser(description=
        "Trace a function and print trace messages",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
parser.add_argument("-p", "--pid", type=int,
        help="id of the process to trace (optional)")
parser.add_argument("-v", "--verbose", action="store_true",
        help="print the BPF program")
parser.add_argument(metavar="probe", dest="probes", nargs="+",
        help="probe specifier (see examples)")
args = parser.parse_args()

probes = []
for probe_spec in args.probes:
        probes.append(Probe(probe_spec))

for probe in probes:
        print(probe)

program = "#include <linux/ptrace.h>\n"
for probe in probes:
        program += probe.generate_program(args.pid or -1)

if args.verbose:
        print(program)

bpf = BPF(text=program)

for probe in probes:
        probe.attach(bpf)

while True:
        # TODO read events from BPF_PERF
        try:
                (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
        except ValueError:
                continue
        print(msg)

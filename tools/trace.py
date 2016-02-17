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
import ctypes as ct

MAX_STRING_SIZE = 64   # TODO Make this configurable

class Probe(object):
        probe_count = 0

        def __init__(self, probe):
                self.raw_probe = probe
                Probe.probe_count += 1
                self._parse_probe()
                self.probe_num = Probe.probe_count
                self.probe_name = "probe_%s_%d" % \
                                (self.function, self.probe_num)

        def __str__(self):
                return "%s:%s`%s FLT=%s ACT=%s/%s" % (self.probe_type,
                        self.library, self.function, self.filter,
                        self.types, self.values)

        def _bail(self, error):
                raise ValueError("error parsing probe %s: %s" %
                                 (self.raw_probe, error))

        def _parse_probe(self):
                text = self.raw_probe

                # Everything until the first space is the probe specifier
                first_space = text.find(' ')
                spec = text[:first_space] if first_space >= 0 else text
                self._parse_spec(spec)
                if first_space >= 0:
                        text = text[first_space:].lstrip()
                else:
                        text = ""

                # If we now have a (, wait for the balanced closing ) and that
                # will be the predicate
                self.filter = None
                if len(text) > 0 and text[0] == "(":
                        balance = 1
                        for i in range(1, len(text)):
                                if text[i] == "(":
                                        balance += 1
                                if text[i] == ")":
                                        balance -= 1
                                if balance == 0:
                                        self._parse_filter(text[:i+1])
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
                self.filter = self._replace_args(filt)

        def _parse_types(self, fmt):
                for match in re.finditer(r'[^%]%(s|u|d|llu|lld|hu|hd|c)', fmt):
                        self.types.append(match.group(1))
                self.python_format = re.sub(
                                r'([^%]%)(u|d|llu|lld|hu|hd)', r'\1d', fmt)
                self.python_format = self.python_format.strip('"')

        def _parse_action(self, action):
                self.values = []
                self.types = []
                self.python_format = ""
                if len(action) == 0:
                        return

                parts = action.split(',')
                self.raw_format = parts[0]
                self._parse_types(self.raw_format)
                for part in parts[1:]:
                        part = self._replace_args(part)
                        self.values.append(part)

        def _replace_args(self, expr):
                expr = expr.replace("retval", "ctx->ax")
                expr = expr.replace("arg1", "ctx->di")
                expr = expr.replace("arg2", "ctx->si")
                expr = expr.replace("arg3", "ctx->dx")
                expr = expr.replace("arg4", "ctx->cx")
                # TODO More args? Don't replace inside format string?
                return expr

        p_type = { "u": "ct.c_uint", "d": "ct.c_int",
                   "llu": "ct.c_ulonglong", "lld": "ct.c_longlong",
                   "hu": "ct.c_ushort", "hd": "ct.c_short",
                   "c": "ct.c_ubyte" }

        def _generate_python_field_decl(self, idx):
                field_type = self.types[idx]
                if field_type == "s":
                        ptype = "ct.c_char * %d" % MAX_STRING_SIZE
                else:
                        ptype = Probe.p_type[field_type]
                return "(\"v%d\", %s)" % (idx, ptype)

        def _generate_python_data_decl(self):
                self.python_struct_name = "%s_%d_Data" % \
                                (self.function, self.probe_num)
                text = """
class %s(ct.Structure):
        _fields_ = [
                ("timestamp_ns", ct.c_ulonglong),
                ("pid", ct.c_uint),
%s
        ]
"""
                custom_fields = ""
                for i, field_type in enumerate(self.types):
                        custom_fields += "                %s," % \
                                         self._generate_python_field_decl(i)
                return text % (self.python_struct_name, custom_fields)

        c_type = { "u": "unsigned int", "d": "int",
                   "llu": "unsigned long long", "lld": "long long",
                   "hu": "unsigned short", "hd": "short",
                   "c": "char" }
        fmt_types = c_type.keys()

        def _generate_field_decl(self, idx):
                field_type = self.types[idx]
                if field_type == "s":
                        return "char v%d[%d];\n" % (idx, MAX_STRING_SIZE)
                if field_type in Probe.fmt_types:
                        return "%s v%d;\n" % (Probe.c_type[field_type], idx)
                self._bail("unrecognized format specifier %s" % field_type)

        def _generate_data_decl(self):
                # The BPF program will populate values into the struct
                # according to the format string, and the Python program will
                # construct the final display string.
                self.events_name = "%s_events" % self.probe_name
                self.struct_name = "%s_data_t" % self.probe_name

                data_fields = ""
                for i, field_type in enumerate(self.types):
                        data_fields += "        " + \
                                       self._generate_field_decl(i)

                text = """
struct %s
{
        u64 timestamp_ns;
        u32 pid;
%s
};

BPF_PERF_OUTPUT(%s);
"""
                return text % (self.struct_name, data_fields, self.events_name)

        def _generate_field_assign(self, idx):
                field_type = self.types[idx]
                expr = self.values[idx]
                if field_type == "s":
                        return """
        if (%s != 0) {
                bpf_probe_read(&__data.v%d, sizeof(__data.v%d), (void *)%s);
        }
"""                     % (expr, idx, idx, expr)
                        # return ("bpf_probe_read(&__data.v%d, " + \
                        # "sizeof(__data.v%d), (char*)%s);\n") % (idx, idx, expr)
                        # return ("__builtin_memcpy(&__data.v%d, (void *)%s, " + \
                        #        "sizeof(__data.v%d));\n") % (idx, expr, idx)
                if field_type in Probe.fmt_types:
                        return "__data.v%d = (%s)%s;\n" % \
                                        (idx, Probe.c_type[field_type], expr)
                self._bail("unrecognized field type %s" % field_type)

        def generate_program(self, pid):
                data_decl = self._generate_data_decl()
                self.pid = pid
                if len(self.library) == 0 and pid != -1:
                        pid_filter = """
        u32 __pid = bpf_get_current_pid_tgid();
        if (__pid != %d) { return 0; }
"""             % pid
                else:
                        pid_filter = ""

                data_fields = ""
                for i, expr in enumerate(self.values):
                        data_fields += self._generate_field_assign(i)

                text = """
int %s(struct pt_regs *ctx)
{
        %s
        if (!(%s)) return 0;
        struct %s __data = {0};
        __data.timestamp_ns = bpf_ktime_get_ns();         /* Necessary? */
        __data.pid = bpf_get_current_pid_tgid();
        %s
        %s.perf_submit(ctx, &__data, sizeof(__data));
        return 0;
}
"""
                text = text % (self.probe_name, pid_filter,
                               self.filter, self.struct_name,
                               data_fields, self.events_name)

                return data_decl + "\n" + text

        def _comm(self, pid):
                try:
                        with open("/proc/%d/comm" % pid) as c:
                                return c.read().strip()
                except IOError:
                        return "<unknown>"

        def print_event(self, cpu, data, size):
                # Cast as the generated structure type and display
                # according to the format string in the probe.

                event = eval("ct.cast(data, ct.POINTER(%s)).contents" % \
                                self.python_struct_name)
                fields = ",".join(map(lambda i: "event.v%d" % i,
                                      range(0, len(self.values))))
                msg = eval("self.python_format % (" + fields + ")")
                print("%-10s %-6d %-12s %-12s %s" % \
                        (strftime("%H:%M:%S"), event.pid,
                         self._comm(event.pid)[:12], self.function[:12], msg))

        def attach(self, bpf, verbose):
                if len(self.library) == 0:
                        self._attach_k(bpf)
                else:
                        self._attach_u(bpf)
                python_decl = self._generate_python_data_decl()
                if verbose:
                        print(python_decl)
                exec(self._generate_python_data_decl(), globals(), globals())
                bpf[self.events_name].open_perf_buffer(self.print_event)

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

program = """
#include <linux/ptrace.h>

"""
for probe in probes:
        program += probe.generate_program(args.pid or -1)

if args.verbose:
        print(program)

bpf = BPF(text=program)

for probe in probes:
        print(probe)
        probe.attach(bpf, args.verbose)

# Print header
print("%-10s %-6s %-12s %-12s %s" % ("TIME", "PID", "COMM", "FUNC", "MSG"))

while True:
        bpf.kprobe_poll()

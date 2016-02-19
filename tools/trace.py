#!/usr/bin/env python
#
# trace         Trace a function and print a trace message based on its
#               parameters, with an optional filter.
#
# USAGE: trace [-h] [-p PID] [-v] [-Z STRING_SIZE] [-S] [-M MAX_EVENTS] [-o]
#              probe [probe ...]
# Licensed under the Apache License, Version 2.0 (the "License")
# Copyright (C) 2016 Sasha Goldshtein.

from bcc import BPF
from time import sleep, strftime
import argparse
import re
import ctypes as ct
import os

class Time(object):
        # BPF timestamps come from the monotonic clock. To be able to filter
        # and compare them from Python, we need to invoke clock_gettime.
        # Adapted from http://stackoverflow.com/a/1205762
        CLOCK_MONOTONIC_RAW = 4         # see <linux/time.h>

        class timespec(ct.Structure):
                _fields_ = [
                        ('tv_sec', ct.c_long),
                        ('tv_nsec', ct.c_long)
                ]

        librt = ct.CDLL('librt.so.1', use_errno=True)
        clock_gettime = librt.clock_gettime
        clock_gettime.argtypes = [ct.c_int, ct.POINTER(timespec)]

        @staticmethod
        def monotonic_time():
                t = Time.timespec()
                if Time.clock_gettime(
                        Time.CLOCK_MONOTONIC_RAW, ct.pointer(t)) != 0:
                        errno_ = ct.get_errno()
                        raise OSError(errno_, os.strerror(errno_))
                return t.tv_sec * 1e9 + t.tv_nsec

class Probe(object):
        probe_count = 0
        max_events = None
        event_count = 0
        first_ts = 0
        use_localtime = True

        @classmethod
        def configure(cls, args):
                cls.max_events = args.max_events
                cls.use_localtime = not args.offset
                cls.first_ts = Time.monotonic_time()

        def __init__(self, probe, string_size):
                self.raw_probe = probe
                self.string_size = string_size
                Probe.probe_count += 1
                self._parse_probe()
                self.probe_num = Probe.probe_count
                self.probe_name = "probe_%s_%d" % \
                                (self.function, self.probe_num)

        def __str__(self):
                return "%s:%s`%s FLT=%s ACT=%s/%s" % (self.probe_type,
                        self.library, self.function, self.filter,
                        self.types, self.values)

        def is_default_action(self):
                return self.python_format == ""

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
                # Two special cases: 'func' means 'p::func', 'lib:func' means
                # 'p:lib:func'. Other combinations need to provide an empty
                # value between delimiters, e.g. 'r::func' for a kretprobe on
                # the function func.
                if len(parts) == 1:
                        parts = ["p", "", parts[0]]
                elif len(parts) == 2:
                        parts = ["p", parts[0], parts[1]]
                if len(parts[0]) == 0:
                        self.probe_type = "p"
                elif parts[0] in ["p", "r"]:
                        self.probe_type = parts[0]
                else:
                        self._bail("expected '', 'p', or 'r', got %s" %
                                   parts[0])
                self.library = parts[1]
                self.function = parts[2]

        def _parse_filter(self, filt):
                self.filter = self._replace_args(filt)

        def _parse_types(self, fmt):
                for match in re.finditer(
                                r'[^%]%(s|u|d|llu|lld|hu|hd|x|llx|c)', fmt):
                        self.types.append(match.group(1))
                fmt = re.sub(r'([^%]%)(u|d|llu|lld|hu|hd)', r'\1d', fmt)
                fmt = re.sub(r'([^%]%)(x|llx)', r'\1x', fmt)
                self.python_format = fmt.strip('"')

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

        aliases = {
                "retval": "ctx->ax",
                "arg1": "ctx->di",
                "arg2": "ctx->si",
                "arg3": "ctx->dx",
                "arg4": "ctx->cx",
                "arg5": "ctx->r8",
                "arg6": "ctx->r9",
                "$uid": "(unsigned)(bpf_get_current_uid_gid() & 0xffffffff)",
                "$gid": "(unsigned)(bpf_get_current_uid_gid() >> 32)",
                "$pid": "(unsigned)(bpf_get_current_pid_tgid() & 0xffffffff)",
                "$tgid": "(unsigned)(bpf_get_current_pid_tgid() >> 32)",
                "$cpu": "bpf_get_smp_processor_id()"
        }

        def _replace_args(self, expr):
                for alias, replacement in Probe.aliases.items():
                        expr = expr.replace(alias, replacement)
                return expr

        p_type = { "u": ct.c_uint, "d": ct.c_int,
                   "llu": ct.c_ulonglong, "lld": ct.c_longlong,
                   "hu": ct.c_ushort, "hd": ct.c_short,
                   "x": ct.c_uint, "llx": ct.c_ulonglong,
                   "c": ct.c_ubyte }

        def _generate_python_field_decl(self, idx, fields):
                field_type = self.types[idx]
                if field_type == "s":
                        ptype = ct.c_char * self.string_size
                else:
                        ptype = Probe.p_type[field_type]
                fields.append(("v%d" % idx, ptype))

        def _generate_python_data_decl(self):
                self.python_struct_name = "%s_%d_Data" % \
                                (self.function, self.probe_num)
                fields = [
                        ("timestamp_ns", ct.c_ulonglong),
                        ("pid", ct.c_uint),
                        ("comm", ct.c_char * 16)       # TASK_COMM_LEN
                ]
                for i in range(0, len(self.types)):
                        self._generate_python_field_decl(i, fields)
                return type(self.python_struct_name, (ct.Structure,),
                            dict(_fields_=fields))

        c_type = { "u": "unsigned int", "d": "int",
                   "llu": "unsigned long long", "lld": "long long",
                   "hu": "unsigned short", "hd": "short",
                   "x": "unsigned int", "llx": "unsigned long long",
                   "c": "char" }
        fmt_types = c_type.keys()

        def _generate_field_decl(self, idx):
                field_type = self.types[idx]
                if field_type == "s":
                        return "char v%d[%d];\n" % (idx, self.string_size)
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
        char comm[TASK_COMM_LEN];
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
                        return "        __data.v%d = (%s)%s;\n" % \
                                        (idx, Probe.c_type[field_type], expr)
                self._bail("unrecognized field type %s" % field_type)

        def generate_program(self, pid, include_self):
                data_decl = self._generate_data_decl()
                self.pid = pid
                # kprobes don't have built-in pid filters, so we have to add
                # it to the function body:
                if len(self.library) == 0 and pid != -1:
                        pid_filter = """
        u32 __pid = bpf_get_current_pid_tgid();
        if (__pid != %d) { return 0; }
"""             % pid
                elif not include_self:
                        pid_filter = """
        u32 __pid = bpf_get_current_pid_tgid();
        if (__pid == %d) { return 0; }
"""             % os.getpid()
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
        __data.timestamp_ns = bpf_ktime_get_ns();
        __data.pid = bpf_get_current_pid_tgid();
        bpf_get_current_comm(&__data.comm, sizeof(__data.comm));
%s
        %s.perf_submit(ctx, &__data, sizeof(__data));
        return 0;
}
"""
                text = text % (self.probe_name, pid_filter,
                               self.filter, self.struct_name,
                               data_fields, self.events_name)

                return data_decl + "\n" + text

        @classmethod
        def _time_off_str(cls, timestamp_ns):
                return "%.6f" % (1e-9 * (timestamp_ns - cls.first_ts))

        def print_event(self, cpu, data, size):
                # Cast as the generated structure type and display
                # according to the format string in the probe.
                event = ct.cast(data, ct.POINTER(self.python_struct)).contents
                values = map(lambda i: getattr(event, "v%d" % i),
                             range(0, len(self.values)))
                msg = self.python_format % tuple(values)
                time = strftime("%H:%M:%S") if Probe.use_localtime else \
                       Probe._time_off_str(event.timestamp_ns)
                print("%-8s %-6d %-12s %-16s %s" % \
                    (time[:8], event.pid, event.comm[:12], self.function, msg))

                Probe.event_count += 1
                if Probe.max_events is not None and \
                   Probe.event_count >= Probe.max_events:
                        exit()

        def attach(self, bpf, verbose):
                if len(self.library) == 0:
                        self._attach_k(bpf)
                else:
                        self._attach_u(bpf)
                self.python_struct = self._generate_python_data_decl()
                bpf[self.events_name].open_perf_buffer(self.print_event)

        def _attach_k(self, bpf):
                if self.probe_type == "r":
                        bpf.attach_kretprobe(event=self.function,
                                             fn_name=self.probe_name)
                elif self.probe_type == "p":
                        bpf.attach_kprobe(event=self.function,
                                          fn_name=self.probe_name)

        def _attach_u(self, bpf):
                libpath = BPF.find_library(self.library)
                if libpath is None:
                        # This might be an executable (e.g. 'bash')
                        with os.popen("/usr/bin/which %s 2>/dev/null" %
                                      self.library) as w:
                                libpath = w.read().strip()
                if libpath is None or len(libpath) == 0:
                        self._bail("unable to find library %s" % self.library)

                if self.probe_type == "r":
                        bpf.attach_uretprobe(name=libpath,
                                             sym=self.function,
                                             fn_name=self.probe_name,
                                             pid=self.pid)
                else:
                        bpf.attach_uprobe(name=libpath,
                                          sym=self.function,
                                          fn_name=self.probe_name,
                                          pid=self.pid)

examples = """
EXAMPLES:

trace ::do_sys_open
        Trace the open syscall and print a default trace message when entered
trace '::do_sys_open "%s", arg2'
        Trace the open syscall and print the filename being opened
trace '::sys_read (arg3 > 20000) "read %d bytes", arg3'
        Trace the read syscall and print a message for reads >20000 bytes
trace 'r::do_sys_return "%llx", retval'
        Trace the return from the open syscall and print the return value
trace ':c:open (arg2 == 42) "%s %d", arg1, arg2'
        Trace the open() call from libc only if the flags (arg2) argument is 42
trace ':c:malloc "size = %d", arg1'
        Trace malloc calls and print the size being allocated
trace 'r:c:malloc (retval) "allocated = %p", retval
        Trace returns from malloc and print non-NULL allocated buffers
"""

parser = argparse.ArgumentParser(description=
        "Attach to functions and print trace messages.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
parser.add_argument("-p", "--pid", type=int,
        help="id of the process to trace (optional)")
parser.add_argument("-v", "--verbose", action="store_true",
        help="print resulting BPF program code before executing")
parser.add_argument("-Z", "--string-size", type=int, default=80,
        help="maximum size to read from strings")
parser.add_argument("-S", "--include-self", action="store_true",
        help="do not filter trace's own pid from the trace")
parser.add_argument("-M", "--max-events", type=int,
        help="number of events to print before quitting")
parser.add_argument("-o", "--offset", action="store_true",
        help="use relative time from first traced message")
parser.add_argument(metavar="probe", dest="probes", nargs="+",
        help="probe specifier (see examples)")
args = parser.parse_args()

Probe.configure(args)

probes = []
for probe_spec in args.probes:
        probes.append(Probe(probe_spec, args.string_size))

program = """
#include <linux/ptrace.h>
#include <linux/sched.h>        /* For TASK_COMM_LEN */

"""
for probe in probes:
        program += probe.generate_program(args.pid or -1, args.include_self)

if args.verbose:
        print(program)

bpf = BPF(text=program)

for probe in probes:
        if args.verbose:
                print(probe)
        probe.attach(bpf, args.verbose)

all_probes_trivial = all(map(Probe.is_default_action, probes))

# Print header
print("%-8s %-6s %-12s %-16s %s" % ("TIME", "PID", "COMM", "FUNC",
      "-" if not all_probes_trivial else ""))

while True:
        bpf.kprobe_poll()


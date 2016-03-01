#!/usr/bin/env python
#
# trace         Trace a function and print a trace message based on its
#               parameters, with an optional filter.
#
# USAGE: trace [-h] [-p PID] [-v] [-Z STRING_SIZE] [-S] [-M MAX_EVENTS] [-o]
#              probe [probe ...]
#
# Licensed under the Apache License, Version 2.0 (the "License")
# Copyright (C) 2016 Sasha Goldshtein.

from bcc import BPF
from time import sleep, strftime
import argparse
import re
import ctypes as ct
import multiprocessing
import os
import traceback
import sys

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

class Perf(object):
        class perf_event_attr(ct.Structure):
                _fields_ = [
                        ('type', ct.c_uint),
                        ('size', ct.c_uint),
                        ('config', ct.c_ulong),
                        ('sample_period', ct.c_ulong),
                        ('sample_type', ct.c_ulong),
                        ('IGNORE1', ct.c_ulong),
                        ('IGNORE2', ct.c_ulong),
                        ('wakeup_events', ct.c_uint),
                        ('IGNORE3', ct.c_uint),
                        ('IGNORE4', ct.c_ulong),
                        ('IGNORE5', ct.c_ulong),
                        ('IGNORE6', ct.c_ulong),
                        ('IGNORE7', ct.c_uint),
                        ('IGNORE8', ct.c_int),
                        ('IGNORE9', ct.c_ulong),
                        ('IGNORE10', ct.c_uint),
                        ('IGNORE11', ct.c_uint)
                ]

        NR_PERF_EVENT_OPEN = 298
        PERF_TYPE_TRACEPOINT = 2
        PERF_SAMPLE_RAW = 1024
        PERF_FLAG_FD_CLOEXEC = 8
        PERF_EVENT_IOC_SET_FILTER = 1074275334
        PERF_EVENT_IOC_ENABLE = 9216

        libc = ct.CDLL('libc.so.6', use_errno=True)
        syscall = libc.syscall          # not declaring vararg types
        ioctl = libc.ioctl              # not declaring vararg types

        @staticmethod
        def _open_for_cpu(cpu, attr):
                pfd = Perf.syscall(Perf.NR_PERF_EVENT_OPEN, ct.byref(attr),
                                   -1, cpu, -1, Perf.PERF_FLAG_FD_CLOEXEC)
                if pfd < 0:
                        errno_ = ct.get_errno()
                        raise OSError(errno_, os.strerror(errno_))
                if Perf.ioctl(pfd, Perf.PERF_EVENT_IOC_SET_FILTER,
                              "common_pid == -17") < 0:
                        errno_ = ct.get_errno()
                        raise OSError(errno_, os.strerror(errno_))
                if Perf.ioctl(pfd, Perf.PERF_EVENT_IOC_ENABLE, 0) < 0:
                        errno_ = ct.get_errno()
                        raise OSError(errno_, os.strerror(errno_))

        @staticmethod
        def perf_event_open(tpoint_id):
                attr = Perf.perf_event_attr()
                attr.config = tpoint_id
                attr.type = Perf.PERF_TYPE_TRACEPOINT
                attr.sample_type = Perf.PERF_SAMPLE_RAW
                attr.sample_period = 1
                attr.wakeup_events = 1
                for cpu in range(0, multiprocessing.cpu_count()):
                        Perf._open_for_cpu(cpu, attr)

class Tracepoint(object):
        tracepoints_enabled = 0
        trace_root = "/sys/kernel/debug/tracing"
        event_root = os.path.join(trace_root, "events")

        @staticmethod
        def generate_decl():
                if Tracepoint.tracepoints_enabled == 0:
                        return ""
                return "\nBPF_HASH(__trace_di, u64, u64);\n"

        @staticmethod
        def generate_entry_probe():
                if Tracepoint.tracepoints_enabled == 0:
                        return ""
                return """
int __trace_entry_update(struct pt_regs *ctx)
{
        u64 tid = bpf_get_current_pid_tgid();
        u64 val = ctx->di;
        __trace_di.update(&tid, &val);
        return 0;
}
"""

        @staticmethod
        def enable_tracepoint(category, event):
                tp_id = Tracepoint.get_tpoint_id(category, event)
                if tp_id == -1:
                        raise ValueError("no such tracepoint found: %s:%s" %
                                         (category, event))
                Perf.perf_event_open(tp_id)
                Tracepoint.tracepoints_enabled += 1

        @staticmethod
        def get_tpoint_id(category, event):
                evt_dir = os.path.join(Tracepoint.event_root, category, event)
                try:
                        return int(
                          open(os.path.join(evt_dir, "id")).read().strip())
                except:
                        return -1

        @staticmethod
        def get_tpoint_format(category, event):
                evt_dir = os.path.join(Tracepoint.event_root, category, event)
                try:
                        return open(os.path.join(evt_dir, "format")).readlines()
                except:
                        return ""

        @staticmethod
        def attach(bpf):
                if Tracepoint.tracepoints_enabled > 0:
                        bpf.attach_kprobe(event="tracing_generic_entry_update",
                                          fn_name="__trace_entry_update")

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

        def _generate_tpoint_entry_struct_fields(self):
                format_lines = Tracepoint.get_tpoint_format(self.tp_category,
                                                            self.tp_event)
                text = ""
                for line in format_lines:
                        match = re.search(r'field:([^;]*);.*size:(\d+);', line)
                        if match is None:
                                continue
                        parts = match.group(1).split()
                        field_name = parts[-1:][0]
                        field_type = " ".join(parts[:-1])
                        field_size = int(match.group(2))
                        if "__data_loc" in field_type:
                                continue
                        if field_name.startswith("common_"):
                                continue
                        text += "        %s %s;\n" % (field_type, field_name)
                return text

        def _generate_tpoint_entry_struct(self):
                text = """
struct %s {
        u64 __do_not_use__;
%s
};
                """
                self.tp_entry_struct_name = self.probe_name + \
                                            "_trace_entry"
                fields = self._generate_tpoint_entry_struct_fields()
                return text % (self.tp_entry_struct_name, fields)

        def _generate_tpoint_entry_prefix(self):
                text = """
        u64 tid = bpf_get_current_pid_tgid();
        u64 *di = __trace_di.lookup(&tid);
        if (di == 0) { return 0; }
        struct %s tp = {};
        bpf_probe_read(&tp, sizeof(tp), (void *)*di);
                """ % self.tp_entry_struct_name
                return text

        def _bail(self, error):
                raise ValueError("error parsing probe '%s': %s" %
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
                elif parts[0] in ["p", "r", "t"]:
                        self.probe_type = parts[0]
                else:
                        self._bail("expected '', 'p', 't', or 'r', got '%s'" %
                                   parts[0])
                if self.probe_type == "t":
                        self.tp_category = parts[1]
                        self.tp_event = parts[2]
                        Tracepoint.enable_tracepoint(self.tp_category,
                                                     self.tp_event)
                        self.library = ""       # kernel
                        self.function = "perf_trace_%s" % self.tp_event
                else:
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

                action = action.strip()
                match = re.search(r'(\".*\"),?(.*)', action)
                if match is None:
                        self._bail("expected format string in \"s")

                self.raw_format = match.group(1)
                self._parse_types(self.raw_format)
                for part in match.group(2).split(','):
                        part = self._replace_args(part)
                        if len(part) > 0:
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

                prefix = ""
                if self.probe_type == "t":
                        data_decl += self._generate_tpoint_entry_struct()
                        prefix = self._generate_tpoint_entry_prefix()

                text = """
int %s(struct pt_regs *ctx)
{
        %s
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
                text = text % (self.probe_name, pid_filter, prefix,
                               self.filter, self.struct_name,
                               data_fields, self.events_name)

                return data_decl + "\n" + text

        @classmethod
        def _time_off_str(cls, timestamp_ns):
                return "%.6f" % (1e-9 * (timestamp_ns - cls.first_ts))

        auto_includes = {
                "linux/time.h"      : ["time"],
                "linux/fs.h"        : ["fs", "file"],
                "linux/blkdev.h"    : ["bio", "request"],
                "linux/slab.h"      : ["alloc"],
                "linux/netdevice.h" : ["sk_buff"]
        }

        @classmethod
        def generate_auto_includes(cls, probes):
                headers = ""
                for header, keywords in cls.auto_includes.items():
                        for keyword in keywords:
                                for probe in probes:
                                        if keyword in probe:
                                                headers += "#include <%s>\n" \
                                                           % header
                return headers

        def _display_function(self):
                if self.probe_type != 't':
                        return self.function
                else:
                        return self.function.replace("perf_trace_", "")

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
                    (time[:8], event.pid, event.comm[:12],
                     self._display_function(), msg))

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
                elif self.probe_type == "p" or self.probe_type == "t":
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

class Tool(object):
        examples = """
EXAMPLES:

trace do_sys_open
        Trace the open syscall and print a default trace message when entered
trace 'do_sys_open "%s", arg2'
        Trace the open syscall and print the filename being opened
trace 'sys_read (arg3 > 20000) "read %d bytes", arg3'
        Trace the read syscall and print a message for reads >20000 bytes
trace 'r::do_sys_return "%llx", retval'
        Trace the return from the open syscall and print the return value
trace 'c:open (arg2 == 42) "%s %d", arg1, arg2'
        Trace the open() call from libc only if the flags (arg2) argument is 42
trace 'c:malloc "size = %d", arg1'
        Trace malloc calls and print the size being allocated
trace 'p:c:write (arg1 == 1) "writing %d bytes to STDOUT", arg3'
        Trace the write() call from libc to monitor writes to STDOUT
trace 'r::__kmalloc (retval == 0) "kmalloc failed!"
        Trace returns from __kmalloc which returned a null pointer
trace 'r:c:malloc (retval) "allocated = %p", retval
        Trace returns from malloc and print non-NULL allocated buffers
trace 't:block:block_rq_complete "sectors=%d", tp.nr_sector'
        Trace the block_rq_complete kernel tracepoint and print # of tx sectors
"""

        def __init__(self):
                parser = argparse.ArgumentParser(description=
                        "Attach to functions and print trace messages.",
                        formatter_class=argparse.RawDescriptionHelpFormatter,
                        epilog=Tool.examples)
                parser.add_argument("-p", "--pid", type=int,
                  help="id of the process to trace (optional)")
                parser.add_argument("-v", "--verbose", action="store_true",
                  help="print resulting BPF program code before executing")
                parser.add_argument("-Z", "--string-size", type=int,
                  default=80, help="maximum size to read from strings")
                parser.add_argument("-S", "--include-self", action="store_true",
                  help="do not filter trace's own pid from the trace")
                parser.add_argument("-M", "--max-events", type=int,
                  help="number of events to print before quitting")
                parser.add_argument("-o", "--offset", action="store_true",
                  help="use relative time from first traced message")
                parser.add_argument(metavar="probe", dest="probes", nargs="+",
                  help="probe specifier (see examples)")
                self.args = parser.parse_args()

        def _create_probes(self):
                Probe.configure(self.args)
                self.probes = []
                for probe_spec in self.args.probes:
                        self.probes.append(Probe(
                                probe_spec, self.args.string_size))

        def _generate_program(self):
                self.program = """
#include <linux/ptrace.h>
#include <linux/sched.h>        /* For TASK_COMM_LEN */

"""
                self.program += Probe.generate_auto_includes(
                        map(lambda p: p.raw_probe, self.probes))
                self.program += Tracepoint.generate_decl()
                self.program += Tracepoint.generate_entry_probe()
                for probe in self.probes:
                        self.program += probe.generate_program(
                                self.args.pid or -1, self.args.include_self)

                if self.args.verbose:
                        print(self.program)

        def _attach_probes(self):
                self.bpf = BPF(text=self.program)
                Tracepoint.attach(self.bpf)
                for probe in self.probes:
                        if self.args.verbose:
                                print(probe)
                        probe.attach(self.bpf, self.args.verbose)

        def _main_loop(self):
                all_probes_trivial = all(map(Probe.is_default_action,
                                             self.probes))

                # Print header
                print("%-8s %-6s %-12s %-16s %s" % \
                      ("TIME", "PID", "COMM", "FUNC",
                      "-" if not all_probes_trivial else ""))

                while True:
                        self.bpf.kprobe_poll()

        def run(self):
                try:
                        self._create_probes()
                        self._generate_program()
                        self._attach_probes()
                        self._main_loop()
                except:
                        if self.args.verbose:
                                traceback.print_exc()
                        elif sys.exc_type is not SystemExit:
                                print(sys.exc_value)

if __name__ == "__main__":
       Tool().run()

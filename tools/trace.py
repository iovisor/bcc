#!/usr/bin/env python
#
# trace         Trace a function and print a trace message based on its
#               parameters, with an optional filter.
#
# usage: trace [-h] [-p PID] [-L TID] [-v] [-Z STRING_SIZE] [-S]
#              [-M MAX_EVENTS] [-T] [-t] [-K] [-U] [-I header]
#              probe [probe ...]
#
# Licensed under the Apache License, Version 2.0 (the "License")
# Copyright (C) 2016 Sasha Goldshtein.

from bcc import BPF, USDT
from functools import partial
from time import sleep, strftime
import argparse
import re
import ctypes as ct
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

class Probe(object):
        probe_count = 0
        streq_index = 0
        max_events = None
        event_count = 0
        first_ts = 0
        use_localtime = True
        tgid = -1
        pid = -1

        @classmethod
        def configure(cls, args):
                cls.max_events = args.max_events
                cls.print_time = args.timestamp or args.time
                cls.use_localtime = not args.timestamp
                cls.first_ts = Time.monotonic_time()
                cls.tgid = args.tgid or -1
                cls.pid = args.pid or -1

        def __init__(self, probe, string_size, kernel_stack, user_stack):
                self.usdt = None
                self.streq_functions = ""
                self.raw_probe = probe
                self.string_size = string_size
                self.kernel_stack = kernel_stack
                self.user_stack = user_stack
                Probe.probe_count += 1
                self._parse_probe()
                self.probe_num = Probe.probe_count
                self.probe_name = "probe_%s_%d" % \
                                (self._display_function(), self.probe_num)
                self.probe_name = re.sub(r'[^A-Za-z0-9_]', '_', self.probe_name)

        def __str__(self):
                return "%s:%s:%s FLT=%s ACT=%s/%s" % (self.probe_type,
                        self.library, self._display_function(), self.filter,
                        self.types, self.values)

        def is_default_action(self):
                return self.python_format == ""

        def _bail(self, error):
                raise ValueError("error in probe '%s': %s" %
                                 (self.raw_probe, error))

        def _parse_probe(self):
                text = self.raw_probe

                # There might be a function signature preceding the actual
                # filter/print part, or not. Find the probe specifier first --
                # it ends with either a space or an open paren ( for the
                # function signature part.
                #                                          opt. signature
                #                               probespec       |      rest
                #                               ---------  ----------   --
                (spec, sig, rest) = re.match(r'([^ \t\(]+)(\([^\(]*\))?(.*)',
                                             text).groups()

                self._parse_spec(spec)
                self.signature = sig[1:-1] if sig else None # remove the parens
                if self.signature and self.probe_type in ['u', 't']:
                        self._bail("USDT and tracepoint probes can't have " +
                                   "a function signature; use arg1, arg2, " +
                                   "... instead")

                text = rest.lstrip()
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
                                        self._parse_filter(text[:i + 1])
                                        text = text[i + 1:]
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
                elif parts[0] in ["p", "r", "t", "u"]:
                        self.probe_type = parts[0]
                else:
                        self._bail("probe type must be '', 'p', 't', 'r', " +
                                   "or 'u', but got '%s'" % parts[0])
                if self.probe_type == "t":
                        self.tp_category = parts[1]
                        self.tp_event = parts[2]
                        self.library = ""       # kernel
                        self.function = ""      # from TRACEPOINT_PROBE
                elif self.probe_type == "u":
                        self.library = parts[1]
                        self.usdt_name = parts[2]
                        self.function = ""      # no function, just address
                        # We will discover the USDT provider by matching on
                        # the USDT name in the specified library
                        self._find_usdt_probe()
                else:
                        self.library = parts[1]
                        self.function = parts[2]

        def _find_usdt_probe(self):
                target = Probe.pid if Probe.pid and Probe.pid != -1 \
                                   else Probe.tgid
                self.usdt = USDT(path=self.library, pid=target)
                for probe in self.usdt.enumerate_probes():
                        if probe.name == self.usdt_name:
                                return  # Found it, will enable later
                self._bail("unrecognized USDT probe %s" % self.usdt_name)

        def _parse_filter(self, filt):
                self.filter = self._rewrite_expr(filt)

        def _parse_types(self, fmt):
                for match in re.finditer(
                            r'[^%]%(s|u|d|llu|lld|hu|hd|x|llx|c|K|U)', fmt):
                        self.types.append(match.group(1))
                fmt = re.sub(r'([^%]%)(u|d|llu|lld|hu|hd)', r'\1d', fmt)
                fmt = re.sub(r'([^%]%)(x|llx)', r'\1x', fmt)
                fmt = re.sub('%K|%U', '%s', fmt)
                self.python_format = fmt.strip('"')

        def _parse_action(self, action):
                self.values = []
                self.types = []
                self.python_format = ""
                if len(action) == 0:
                        return

                action = action.strip()
                match = re.search(r'(\".*?\"),?(.*)', action)
                if match is None:
                        self._bail("expected format string in \"s")

                self.raw_format = match.group(1)
                self._parse_types(self.raw_format)
                for part in re.split('(?<!"),', match.group(2)):
                        part = self._rewrite_expr(part)
                        if len(part) > 0:
                                self.values.append(part)

        aliases = {
                "retval": "PT_REGS_RC(ctx)",
                "arg1": "PT_REGS_PARM1(ctx)",
                "arg2": "PT_REGS_PARM2(ctx)",
                "arg3": "PT_REGS_PARM3(ctx)",
                "arg4": "PT_REGS_PARM4(ctx)",
                "arg5": "PT_REGS_PARM5(ctx)",
                "arg6": "PT_REGS_PARM6(ctx)",
                "$uid": "(unsigned)(bpf_get_current_uid_gid() & 0xffffffff)",
                "$gid": "(unsigned)(bpf_get_current_uid_gid() >> 32)",
                "$pid": "(unsigned)(bpf_get_current_pid_tgid() & 0xffffffff)",
                "$tgid": "(unsigned)(bpf_get_current_pid_tgid() >> 32)",
                "$cpu": "bpf_get_smp_processor_id()"
        }

        def _generate_streq_function(self, string):
                fname = "streq_%d" % Probe.streq_index
                Probe.streq_index += 1
                self.streq_functions += """
static inline bool %s(char const *ignored, uintptr_t str) {
        char needle[] = %s;
        char haystack[sizeof(needle)];
        bpf_probe_read(&haystack, sizeof(haystack), (void *)str);
        for (int i = 0; i < sizeof(needle) - 1; ++i) {
                if (needle[i] != haystack[i]) {
                        return false;
                }
        }
        return true;
}
                """ % (fname, string)
                return fname

        def _rewrite_expr(self, expr):
                for alias, replacement in Probe.aliases.items():
                        # For USDT probes, we replace argN values with the
                        # actual arguments for that probe obtained using
                        # bpf_readarg_N macros emitted at BPF construction.
                        if alias.startswith("arg") and self.probe_type == "u":
                                continue
                        expr = expr.replace(alias, replacement)
                matches = re.finditer('STRCMP\\(("[^"]+\\")', expr)
                for match in matches:
                        string = match.group(1)
                        fname = self._generate_streq_function(string)
                        expr = expr.replace("STRCMP", fname, 1)
                return expr

        p_type = {"u": ct.c_uint, "d": ct.c_int,
                  "llu": ct.c_ulonglong, "lld": ct.c_longlong,
                  "hu": ct.c_ushort, "hd": ct.c_short,
                  "x": ct.c_uint, "llx": ct.c_ulonglong, "c": ct.c_ubyte,
                  "K": ct.c_ulonglong, "U": ct.c_ulonglong}

        def _generate_python_field_decl(self, idx, fields):
                field_type = self.types[idx]
                if field_type == "s":
                        ptype = ct.c_char * self.string_size
                else:
                        ptype = Probe.p_type[field_type]
                fields.append(("v%d" % idx, ptype))

        def _generate_python_data_decl(self):
                self.python_struct_name = "%s_%d_Data" % \
                                (self._display_function(), self.probe_num)
                fields = [
                        ("timestamp_ns", ct.c_ulonglong),
                        ("tgid", ct.c_uint),
                        ("pid", ct.c_uint),
                        ("comm", ct.c_char * 16)       # TASK_COMM_LEN
                ]
                for i in range(0, len(self.types)):
                        self._generate_python_field_decl(i, fields)
                if self.kernel_stack:
                        fields.append(("kernel_stack_id", ct.c_int))
                if self.user_stack:
                        fields.append(("user_stack_id", ct.c_int))
                return type(self.python_struct_name, (ct.Structure,),
                            dict(_fields_=fields))

        c_type = {"u": "unsigned int", "d": "int",
                  "llu": "unsigned long long", "lld": "long long",
                  "hu": "unsigned short", "hd": "short",
                  "x": "unsigned int", "llx": "unsigned long long",
                  "c": "char", "K": "unsigned long long",
                  "U": "unsigned long long"}
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
                self.stacks_name = "%s_stacks" % self.probe_name
                stack_table = "BPF_STACK_TRACE(%s, 1024);" % self.stacks_name \
                              if (self.kernel_stack or self.user_stack) else ""
                data_fields = ""
                for i, field_type in enumerate(self.types):
                        data_fields += "        " + \
                                       self._generate_field_decl(i)

                kernel_stack_str = "       int kernel_stack_id;" \
                                   if self.kernel_stack else ""
                user_stack_str = "       int user_stack_id;" \
                                 if self.user_stack else ""

                text = """
struct %s
{
        u64 timestamp_ns;
        u32 tgid;
        u32 pid;
        char comm[TASK_COMM_LEN];
%s
%s
%s
};

BPF_PERF_OUTPUT(%s);
%s
"""
                return text % (self.struct_name, data_fields,
                               kernel_stack_str, user_stack_str,
                               self.events_name, stack_table)

        def _generate_field_assign(self, idx):
                field_type = self.types[idx]
                expr = self.values[idx].strip()
                text = ""
                if self.probe_type == "u" and expr[0:3] == "arg":
                        text = ("        u64 %s = 0;\n" +
                                "        bpf_usdt_readarg(%s, ctx, &%s);\n") \
                                % (expr, expr[3], expr)

                if field_type == "s":
                        return text + """
        if (%s != 0) {
                bpf_probe_read(&__data.v%d, sizeof(__data.v%d), (void *)%s);
        }
                """ % (expr, idx, idx, expr)
                if field_type in Probe.fmt_types:
                        return text + "        __data.v%d = (%s)%s;\n" % \
                                        (idx, Probe.c_type[field_type], expr)
                self._bail("unrecognized field type %s" % field_type)

        def _generate_usdt_filter_read(self):
            text = ""
            if self.probe_type != "u":
                    return text
            for arg, _ in Probe.aliases.items():
                    if not (arg.startswith("arg") and
                            (arg in self.filter)):
                            continue
                    arg_index = int(arg.replace("arg", ""))
                    arg_ctype = self.usdt.get_probe_arg_ctype(
                            self.usdt_name, arg_index - 1)
                    if not arg_ctype:
                            self._bail("Unable to determine type of {} "
                                       "in the filter".format(arg))
                    text += """
        {} {}_filter;
        bpf_usdt_readarg({}, ctx, &{}_filter);
                    """.format(arg_ctype, arg, arg_index, arg)
                    self.filter = self.filter.replace(
                            arg, "{}_filter".format(arg))
            return text

        def generate_program(self, include_self):
                data_decl = self._generate_data_decl()
                if Probe.pid != -1:
                        pid_filter = """
        if (__pid != %d) { return 0; }
                """ % Probe.pid
                # uprobes can have a built-in tgid filter passed to
                # attach_uprobe, hence the check here -- for kprobes, we
                # need to do the tgid test by hand:
                elif len(self.library) == 0 and Probe.tgid != -1:
                        pid_filter = """
        if (__tgid != %d) { return 0; }
                """ % Probe.tgid
                elif not include_self:
                        pid_filter = """
        if (__tgid == %d) { return 0; }
                """ % os.getpid()
                else:
                        pid_filter = ""

                prefix = ""
                signature = "struct pt_regs *ctx"
                if self.signature:
                        signature += ", " + self.signature

                data_fields = ""
                for i, expr in enumerate(self.values):
                        data_fields += self._generate_field_assign(i)

                if self.probe_type == "t":
                        heading = "TRACEPOINT_PROBE(%s, %s)" % \
                                  (self.tp_category, self.tp_event)
                        ctx_name = "args"
                else:
                        heading = "int %s(%s)" % (self.probe_name, signature)
                        ctx_name = "ctx"

                stack_trace = ""
                if self.user_stack:
                        stack_trace += """
        __data.user_stack_id = %s.get_stackid(
          %s, BPF_F_REUSE_STACKID | BPF_F_USER_STACK
        );""" % (self.stacks_name, ctx_name)
                if self.kernel_stack:
                        stack_trace += """
        __data.kernel_stack_id = %s.get_stackid(
          %s, BPF_F_REUSE_STACKID
        );""" % (self.stacks_name, ctx_name)

                text = heading + """
{
        u64 __pid_tgid = bpf_get_current_pid_tgid();
        u32 __tgid = __pid_tgid >> 32;
        u32 __pid = __pid_tgid; // implicit cast to u32 for bottom half
        %s
        %s
        %s
        if (!(%s)) return 0;

        struct %s __data = {0};
        __data.timestamp_ns = bpf_ktime_get_ns();
        __data.tgid = __tgid;
        __data.pid = __pid;
        bpf_get_current_comm(&__data.comm, sizeof(__data.comm));
%s
%s
        %s.perf_submit(%s, &__data, sizeof(__data));
        return 0;
}
"""
                text = text % (pid_filter, prefix,
                               self._generate_usdt_filter_read(), self.filter,
                               self.struct_name, data_fields,
                               stack_trace, self.events_name, ctx_name)

                return self.streq_functions + data_decl + "\n" + text

        @classmethod
        def _time_off_str(cls, timestamp_ns):
                return "%.6f" % (1e-9 * (timestamp_ns - cls.first_ts))

        def _display_function(self):
                if self.probe_type == 'p' or self.probe_type == 'r':
                        return self.function
                elif self.probe_type == 'u':
                        return self.usdt_name
                else:   # self.probe_type == 't'
                        return self.tp_event

        def print_stack(self, bpf, stack_id, tgid):
            if stack_id < 0:
                    print("        %d" % stack_id)
                    return

            stack = list(bpf.get_table(self.stacks_name).walk(stack_id))
            for addr in stack:
                    print("        %016x %s" % (addr, bpf.sym(addr, tgid)))

        def _format_message(self, bpf, tgid, values):
                # Replace each %K with kernel sym and %U with user sym in tgid
                kernel_placeholders = [i for i in xrange(0, len(self.types))
                                       if self.types[i] == 'K']
                user_placeholders = [i for i in xrange(0, len(self.types))
                                     if self.types[i] == 'U']
                for kp in kernel_placeholders:
                        values[kp] = bpf.ksymaddr(values[kp])
                for up in user_placeholders:
                        values[up] = bpf.symaddr(values[up], tgid)
                return self.python_format % tuple(values)

        def print_event(self, bpf, cpu, data, size):
                # Cast as the generated structure type and display
                # according to the format string in the probe.
                event = ct.cast(data, ct.POINTER(self.python_struct)).contents
                values = map(lambda i: getattr(event, "v%d" % i),
                             range(0, len(self.values)))
                msg = self._format_message(bpf, event.tgid, values)
                if not Probe.print_time:
                    print("%-6d %-6d %-12s %-16s %s" %
                          (event.tgid, event.pid, event.comm,
                           self._display_function(), msg))
                else:
                    time = strftime("%H:%M:%S") if Probe.use_localtime else \
                           Probe._time_off_str(event.timestamp_ns)
                    print("%-8s %-6d %-6d %-12s %-16s %s" %
                          (time[:8], event.tgid, event.pid, event.comm,
                           self._display_function(), msg))

                if self.kernel_stack:
                        self.print_stack(bpf, event.kernel_stack_id, -1)
                if self.user_stack:
                        self.print_stack(bpf, event.user_stack_id, event.tgid)
                if self.user_stack or self.kernel_stack:
                        print("")

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
                callback = partial(self.print_event, bpf)
                bpf[self.events_name].open_perf_buffer(callback)

        def _attach_k(self, bpf):
                if self.probe_type == "r":
                        bpf.attach_kretprobe(event=self.function,
                                             fn_name=self.probe_name)
                elif self.probe_type == "p":
                        bpf.attach_kprobe(event=self.function,
                                          fn_name=self.probe_name)
                # Note that tracepoints don't need an explicit attach

        def _attach_u(self, bpf):
                libpath = BPF.find_library(self.library)
                if libpath is None:
                        # This might be an executable (e.g. 'bash')
                        libpath = BPF.find_exe(self.library)
                if libpath is None or len(libpath) == 0:
                        self._bail("unable to find library %s" % self.library)

                if self.probe_type == "u":
                        pass    # Was already enabled by the BPF constructor
                elif self.probe_type == "r":
                        bpf.attach_uretprobe(name=libpath,
                                             sym=self.function,
                                             fn_name=self.probe_name,
                                             pid=Probe.tgid)
                else:
                        bpf.attach_uprobe(name=libpath,
                                          sym=self.function,
                                          fn_name=self.probe_name,
                                          pid=Probe.tgid)

class Tool(object):
        examples = """
EXAMPLES:

trace do_sys_open
        Trace the open syscall and print a default trace message when entered
trace 'do_sys_open "%s", arg2'
        Trace the open syscall and print the filename being opened
trace 'sys_read (arg3 > 20000) "read %d bytes", arg3'
        Trace the read syscall and print a message for reads >20000 bytes
trace 'r::do_sys_open "%llx", retval'
        Trace the return from the open syscall and print the return value
trace 'c:open (arg2 == 42) "%s %d", arg1, arg2'
        Trace the open() call from libc only if the flags (arg2) argument is 42
trace 'c:malloc "size = %d", arg1'
        Trace malloc calls and print the size being allocated
trace 'p:c:write (arg1 == 1) "writing %d bytes to STDOUT", arg3'
        Trace the write() call from libc to monitor writes to STDOUT
trace 'r::__kmalloc (retval == 0) "kmalloc failed!"'
        Trace returns from __kmalloc which returned a null pointer
trace 'r:c:malloc (retval) "allocated = %x", retval'
        Trace returns from malloc and print non-NULL allocated buffers
trace 't:block:block_rq_complete "sectors=%d", args->nr_sector'
        Trace the block_rq_complete kernel tracepoint and print # of tx sectors
trace 'u:pthread:pthread_create (arg4 != 0)'
        Trace the USDT probe pthread_create when its 4th argument is non-zero
trace 'p::SyS_nanosleep(struct timespec *ts) "sleep for %lld ns", ts->tv_nsec'
        Trace the nanosleep syscall and print the sleep duration in ns
"""

        def __init__(self):
                parser = argparse.ArgumentParser(description="Attach to " +
                  "functions and print trace messages.",
                  formatter_class=argparse.RawDescriptionHelpFormatter,
                  epilog=Tool.examples)
                # we'll refer to the userspace concepts of "pid" and "tid" by
                # their kernel names -- tgid and pid -- inside the script
                parser.add_argument("-p", "--pid", type=int, metavar="PID",
                  dest="tgid", help="id of the process to trace (optional)")
                parser.add_argument("-L", "--tid", type=int, metavar="TID",
                  dest="pid", help="id of the thread to trace (optional)")
                parser.add_argument("-v", "--verbose", action="store_true",
                  help="print resulting BPF program code before executing")
                parser.add_argument("-Z", "--string-size", type=int,
                  default=80, help="maximum size to read from strings")
                parser.add_argument("-S", "--include-self",
                  action="store_true",
                  help="do not filter trace's own pid from the trace")
                parser.add_argument("-M", "--max-events", type=int,
                  help="number of events to print before quitting")
                parser.add_argument("-t", "--timestamp", action="store_true",
                  help="print timestamp column (offset from trace start)")
                parser.add_argument("-T", "--time", action="store_true",
                  help="print time column")
                parser.add_argument("-K", "--kernel-stack",
                  action="store_true", help="output kernel stack trace")
                parser.add_argument("-U", "--user-stack",
                  action="store_true", help="output user stack trace")
                parser.add_argument(metavar="probe", dest="probes", nargs="+",
                  help="probe specifier (see examples)")
                parser.add_argument("-I", "--include", action="append",
                  metavar="header",
                  help="additional header files to include in the BPF program")
                self.args = parser.parse_args()
                if self.args.tgid and self.args.pid:
                        parser.error("only one of -p and -t may be specified")

        def _create_probes(self):
                Probe.configure(self.args)
                self.probes = []
                for probe_spec in self.args.probes:
                        self.probes.append(Probe(
                                probe_spec, self.args.string_size,
                                self.args.kernel_stack, self.args.user_stack))

        def _generate_program(self):
                self.program = """
#include <linux/ptrace.h>
#include <linux/sched.h>        /* For TASK_COMM_LEN */

"""
                for include in (self.args.include or []):
                        self.program += "#include <%s>\n" % include
                self.program += BPF.generate_auto_includes(
                        map(lambda p: p.raw_probe, self.probes))
                for probe in self.probes:
                        self.program += probe.generate_program(
                                        self.args.include_self)

                if self.args.verbose:
                        print(self.program)

        def _attach_probes(self):
                usdt_contexts = []
                for probe in self.probes:
                    if probe.usdt:
                        # USDT probes must be enabled before the BPF object
                        # is initialized, because that's where the actual
                        # uprobe is being attached.
                        probe.usdt.enable_probe(
                                probe.usdt_name, probe.probe_name)
                        if self.args.verbose:
                                print(probe.usdt.get_text())
                        usdt_contexts.append(probe.usdt)
                self.bpf = BPF(text=self.program, usdt_contexts=usdt_contexts)
                for probe in self.probes:
                        if self.args.verbose:
                                print(probe)
                        probe.attach(self.bpf, self.args.verbose)

        def _main_loop(self):
                all_probes_trivial = all(map(Probe.is_default_action,
                                             self.probes))

                # Print header
                if self.args.timestamp or self.args.time:
                    print("%-8s %-6s %-6s %-12s %-16s %s" %
                          ("TIME", "PID", "TID", "COMM", "FUNC",
                          "-" if not all_probes_trivial else ""))
                else:
                    print("%-6s %-6s %-12s %-16s %s" %
                          ("PID", "TID", "COMM", "FUNC",
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
                        elif sys.exc_info()[0] is not SystemExit:
                                print(sys.exc_info()[1])

if __name__ == "__main__":
        Tool().run()

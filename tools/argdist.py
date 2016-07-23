#!/usr/bin/env python
#
# argdist   Trace a function and display a distribution of its
#           parameter values as a histogram or frequency count.
#
# USAGE: argdist [-h] [-p PID] [-z STRING_SIZE] [-i INTERVAL]
#                [-n COUNT] [-v] [-T TOP]
#                [-C specifier [specifier ...]]
#                [-H specifier [specifier ...]]
#                [-I header [header ...]]
#
# Licensed under the Apache License, Version 2.0 (the "License")
# Copyright (C) 2016 Sasha Goldshtein.

from bcc import BPF, Tracepoint, Perf, USDT
from time import sleep, strftime
import argparse
import re
import traceback
import os
import sys

class Probe(object):
        next_probe_index = 0
        aliases = { "$PID": "bpf_get_current_pid_tgid()" }

        def _substitute_aliases(self, expr):
                if expr is None:
                        return expr
                for alias, subst in Probe.aliases.items():
                        expr = expr.replace(alias, subst)
                return expr

        def _parse_signature(self):
                params = map(str.strip, self.signature.split(','))
                self.param_types = {}
                for param in params:
                        # If the type is a pointer, the * can be next to the
                        # param name. Other complex types like arrays are not
                        # supported right now.
                        index = param.rfind('*')
                        index = index if index != -1 else param.rfind(' ')
                        param_type = param[0:index+1].strip()
                        param_name = param[index+1:].strip()
                        self.param_types[param_name] = param_type

        def _generate_entry(self):
                self.entry_probe_func = self.probe_func_name + "_entry"
                text = """
int PROBENAME(struct pt_regs *ctx SIGNATURE)
{
        u32 pid = bpf_get_current_pid_tgid();
        PID_FILTER
        COLLECT
        return 0;
}
"""
                text = text.replace("PROBENAME", self.entry_probe_func)
                text = text.replace("SIGNATURE",
                     "" if len(self.signature) == 0 else ", " + self.signature)
                pid_filter = "" if self.is_user or self.pid is None \
                                else "if (pid != %d) { return 0; }" % self.pid
                text = text.replace("PID_FILTER", pid_filter)
                collect = ""
                for pname in self.args_to_probe:
                        param_hash = self.hashname_prefix + pname
                        if pname == "__latency":
                                collect += """
u64 __time = bpf_ktime_get_ns();
%s.update(&pid, &__time);
"""                             % param_hash
                        else:
                                collect += "%s.update(&pid, &%s);\n" % \
                                           (param_hash, pname)
                text = text.replace("COLLECT", collect)
                return text

        def _generate_entry_probe(self):
                # Any $entry(name) expressions result in saving that argument
                # when entering the function.
                self.args_to_probe = set()
                regex = r"\$entry\((\w+)\)"
                for expr in self.exprs:
                        for arg in re.finditer(regex, expr):
                                self.args_to_probe.add(arg.group(1))
                for arg in re.finditer(regex, self.filter):
                        self.args_to_probe.add(arg.group(1))
                if any(map(lambda expr: "$latency" in expr, self.exprs)) or \
                   "$latency" in self.filter:
                        self.args_to_probe.add("__latency")
                        self.param_types["__latency"] = "u64"    # nanoseconds
                for pname in self.args_to_probe:
                        if pname not in self.param_types:
                                raise ValueError("$entry(%s): no such param" \
                                                % arg)

                self.hashname_prefix = "%s_param_" % self.probe_hash_name
                text = ""
                for pname in self.args_to_probe:
                        # Each argument is stored in a separate hash that is
                        # keyed by pid.
                        text += "BPF_HASH(%s, u32, %s);\n" % \
                             (self.hashname_prefix + pname,
                              self.param_types[pname])
                text += self._generate_entry()
                return text

        def _generate_retprobe_prefix(self):
                # After we're done here, there are __%s_val variables for each
                # argument we needed to probe using $entry(name), and they all
                # have values (which isn't necessarily the case if we missed
                # the method entry probe).
                text = "u32 __pid = bpf_get_current_pid_tgid();\n"
                self.param_val_names = {}
                for pname in self.args_to_probe:
                        val_name = "__%s_val" % pname
                        text += "%s *%s = %s.lookup(&__pid);\n" % \
                                (self.param_types[pname], val_name,
                                 self.hashname_prefix + pname)
                        text += "if (%s == 0) { return 0 ; }\n" % val_name
                        self.param_val_names[pname] = val_name
                return text

        def _replace_entry_exprs(self):
                for pname, vname in self.param_val_names.items():
                        if pname == "__latency":
                                entry_expr = "$latency"
                                val_expr = "(bpf_ktime_get_ns() - *%s)" % vname
                        else:
                                entry_expr = "$entry(%s)" % pname
                                val_expr = "(*%s)" % vname
                        for i in range(0, len(self.exprs)):
                                self.exprs[i] = self.exprs[i].replace(
                                                entry_expr, val_expr)
                        self.filter = self.filter.replace(entry_expr,
                                                          val_expr)

        def _attach_entry_probe(self):
                if self.is_user:
                        self.bpf.attach_uprobe(name=self.library,
                                               sym=self.function,
                                               fn_name=self.entry_probe_func,
                                               pid=self.pid or -1)
                else:
                        self.bpf.attach_kprobe(event=self.function,
                                               fn_name=self.entry_probe_func)

        def _bail(self, error):
                raise ValueError("error parsing probe '%s': %s" %
                                 (self.raw_spec, error))

        def _validate_specifier(self):
                # Everything after '#' is the probe label, ignore it
                spec = self.raw_spec.split('#')[0]
                parts = spec.strip().split(':')
                if len(parts) < 3:
                        self._bail("at least the probe type, library, and " +
                                   "function signature must be specified")
                if len(parts) > 6:
                        self._bail("extraneous ':'-separated parts detected")
                if parts[0] not in ["r", "p", "t", "u"]:
                        self._bail("probe type must be 'p', 'r', 't', or 'u' " +
                                   "but got '%s'" % parts[0])
                if re.match(r"\w+\(.*\)", parts[2]) is None:
                        self._bail(("function signature '%s' has an invalid " +
                                    "format") % parts[2])

        def _parse_expr_types(self, expr_types):
                if len(expr_types) == 0:
                        self._bail("no expr types specified")
                self.expr_types = expr_types.split(',')

        def _parse_exprs(self, exprs):
                if len(exprs) == 0:
                        self._bail("no exprs specified")
                self.exprs = exprs.split(',')

        def __init__(self, bpf, type, specifier):
                self.pid = bpf.args.pid
                self.raw_spec = specifier
                self._validate_specifier()

                spec_and_label = specifier.split('#')
                self.label = spec_and_label[1] \
                             if len(spec_and_label) == 2 else None

                parts = spec_and_label[0].strip().split(':')
                self.type = type    # hist or freq
                self.probe_type = parts[0]
                fparts = parts[2].split('(')
                self.function = fparts[0].strip()
                if self.probe_type == "t":
                        self.library = ""       # kernel
                        self.tp_category = parts[1]
                        self.tp_event = self.function
                        self.tp = Tracepoint.enable_tracepoint(
                                        self.tp_category, self.tp_event)
                        self.function = "perf_trace_" + self.function
                elif self.probe_type == "u":
                        self.library = parts[1]
                        self.probe_func_name = "%s_probe%d" % \
                                (self.function, Probe.next_probe_index)
                        bpf.enable_usdt_probe(self.function,
                                        fn_name=self.probe_func_name)
                else:
                        self.library = parts[1]
                self.is_user = len(self.library) > 0
                self.signature = fparts[1].strip()[:-1]
                self._parse_signature()

                # If the user didn't specify an expression to probe, we probe
                # the retval in a ret probe, or simply the value "1" otherwise.
                self.is_default_expr = len(parts) < 5
                if not self.is_default_expr:
                        self._parse_expr_types(parts[3])
                        self._parse_exprs(parts[4])
                        if len(self.exprs) != len(self.expr_types):
                                self._bail("mismatched # of exprs and types")
                        if self.type == "hist" and len(self.expr_types) > 1:
                                self._bail("histograms can only have 1 expr")
                else:
                        if not self.probe_type == "r" and self.type == "hist":
                                self._bail("histograms must have expr")
                        self.expr_types = \
                          ["u64" if not self.probe_type == "r" else "int"]
                        self.exprs = \
                          ["1" if not self.probe_type == "r" else "$retval"]
                self.filter = "" if len(parts) != 6 else parts[5]
                self._substitute_exprs()

                # Do we need to attach an entry probe so that we can collect an
                # argument that is required for an exit (return) probe?
                def check(expr):
                        keywords = ["$entry", "$latency"]
                        return any(map(lambda kw: kw in expr, keywords))
                self.entry_probe_required = self.probe_type == "r" and \
                        (any(map(check, self.exprs)) or check(self.filter))

                self.probe_func_name = "%s_probe%d" % \
                        (self.function, Probe.next_probe_index)
                self.probe_hash_name = "%s_hash%d" % \
                        (self.function, Probe.next_probe_index)
                Probe.next_probe_index += 1

        def close(self):
                pass

        def _substitute_exprs(self):
                def repl(expr):
                        expr = self._substitute_aliases(expr)
                        return expr.replace("$retval", "PT_REGS_RC(ctx)")
                for i in range(0, len(self.exprs)):
                        self.exprs[i] = repl(self.exprs[i])
                self.filter = repl(self.filter)

        def _is_string(self, expr_type):
                return expr_type == "char*" or expr_type == "char *"

        def _generate_hash_field(self, i):
                if self._is_string(self.expr_types[i]):
                        return "struct __string_t v%d;\n" % i
                else:
                        return "%s v%d;\n" % (self.expr_types[i], i)

        def _generate_field_assignment(self, i):
                text = ""
                if self.probe_type == "u" and self.exprs[i][0:3] == "arg":
                    text = ("        u64 %s;\n" + 
                           "        bpf_usdt_readarg(%s, ctx, &%s);\n") % \
                           (self.exprs[i], self.exprs[i][3], self.exprs[i])
                if self._is_string(self.expr_types[i]):
                        return (text + "        bpf_probe_read(&__key.v%d.s," +
                                " sizeof(__key.v%d.s), (void *)%s);\n") % \
                                (i, i, self.exprs[i])
                else:
                        return text + "        __key.v%d = %s;\n" % \
                               (i, self.exprs[i])

        def _generate_hash_decl(self):
                if self.type == "hist":
                        return "BPF_HISTOGRAM(%s, %s);" % \
                               (self.probe_hash_name, self.expr_types[0])
                else:
                        text = "struct %s_key_t {\n" % self.probe_hash_name
                        for i in range(0, len(self.expr_types)):
                                text += self._generate_hash_field(i)
                        text += "};\n"
                        text += "BPF_HASH(%s, struct %s_key_t, u64);\n" % \
                                (self.probe_hash_name, self.probe_hash_name)
                        return text

        def _generate_key_assignment(self):
                if self.type == "hist":
                        return "%s __key = %s;\n" % \
                                (self.expr_types[0], self.exprs[0])
                else:
                        text = "struct %s_key_t __key = {};\n" % \
                                self.probe_hash_name
                        for i in range(0, len(self.exprs)):
                                text += self._generate_field_assignment(i)
                        return text

        def _generate_hash_update(self):
                if self.type == "hist":
                        return "%s.increment(bpf_log2l(__key));" % \
                                self.probe_hash_name
                else:
                        return "%s.increment(__key);" % self.probe_hash_name

        def _generate_pid_filter(self):
                # Kernel probes need to explicitly filter pid, because the
                # attach interface doesn't support pid filtering
                if self.pid is not None and not self.is_user:
                        return "u32 pid = bpf_get_current_pid_tgid();\n" + \
                               "if (pid != %d) { return 0; }" % self.pid
                else:
                        return ""

        def generate_text(self):
                program = ""
                probe_text = """
DATA_DECL

int PROBENAME(struct pt_regs *ctx SIGNATURE)
{
        PID_FILTER
        PREFIX
        if (!(FILTER)) return 0;
        KEY_EXPR
        COLLECT
        return 0;
}
"""
                prefix = ""
                signature = ""

                # If any entry arguments are probed in a ret probe, we need
                # to generate an entry probe to collect them
                if self.entry_probe_required:
                        program += self._generate_entry_probe()
                        prefix += self._generate_retprobe_prefix()
                        # Replace $entry(paramname) with a reference to the
                        # value we collected when entering the function:
                        self._replace_entry_exprs()

                if self.probe_type == "t":
                        program += self.tp.generate_struct()
                        prefix += self.tp.generate_get_struct()
                elif self.probe_type == "p" and len(self.signature) > 0:
                        # Only entry uprobes/kprobes can have user-specified
                        # signatures. Other probes force it to ().
                        signature = ", " + self.signature

                program += probe_text.replace("PROBENAME", self.probe_func_name)
                program = program.replace("SIGNATURE", signature)
                program = program.replace("PID_FILTER",
                                          self._generate_pid_filter())

                decl = self._generate_hash_decl()
                key_expr = self._generate_key_assignment()
                collect = self._generate_hash_update()
                program = program.replace("DATA_DECL", decl)
                program = program.replace("KEY_EXPR", key_expr)
                program = program.replace("FILTER",
                        "1" if len(self.filter) == 0 else self.filter)
                program = program.replace("COLLECT", collect)
                program = program.replace("PREFIX", prefix)

                return program

        def _attach_u(self):
                libpath = BPF.find_library(self.library)
                if libpath is None:
                        libpath = BPF._find_exe(self.library)
                if libpath is None or len(libpath) == 0:
                        self._bail("unable to find library %s" % self.library)

                if self.probe_type == "r":
                        self.bpf.attach_uretprobe(name=libpath,
                                                  sym=self.function,
                                                  fn_name=self.probe_func_name,
                                                  pid=self.pid or -1)
                else:
                        self.bpf.attach_uprobe(name=libpath,
                                               sym=self.function,
                                               fn_name=self.probe_func_name,
                                               pid=self.pid or -1)

        def _attach_k(self):
                if self.probe_type == "r" or self.probe_type == "t":
                        self.bpf.attach_kretprobe(event=self.function,
                                             fn_name=self.probe_func_name)
                else:
                        self.bpf.attach_kprobe(event=self.function,
                                          fn_name=self.probe_func_name)

        def attach(self, bpf):
                self.bpf = bpf
                if self.probe_type == "u": return;
                if self.is_user:
                        self._attach_u()
                else:
                        self._attach_k()
                if self.entry_probe_required:
                        self._attach_entry_probe()

        def _v2s(self, v):
                # Most fields can be converted with plain str(), but strings
                # are wrapped in a __string_t which has an .s field
                if "__string_t" in type(v).__name__:
                        return str(v.s)
                return str(v)

        def _display_expr(self, i):
                # Replace ugly latency calculation with $latency
                expr = self.exprs[i].replace(
                        "(bpf_ktime_get_ns() - *____latency_val)", "$latency")
                # Replace alias values back with the alias name
                for alias, subst in Probe.aliases.items():
                        expr = expr.replace(subst, alias)
                # Replace retval expression with $retval
                expr = expr.replace("PT_REGS_RC(ctx)", "$retval")
                # Replace ugly (*__param_val) expressions with param name
                return re.sub(r"\(\*__(\w+)_val\)", r"\1", expr)

        def _display_key(self, key):
                if self.is_default_expr:
                        if not self.probe_type == "r":
                                return "total calls"
                        else:
                                return "retval = %s" % str(key.v0)
                else:
                        # The key object has v0, ..., vk fields containing
                        # the values of the expressions from self.exprs
                        def str_i(i):
                                key_i = self._v2s(getattr(key, "v%d" % i))
                                return "%s = %s" % \
                                        (self._display_expr(i), key_i)
                        return ", ".join(map(str_i, range(0, len(self.exprs))))

        def display(self, top):
                data = self.bpf.get_table(self.probe_hash_name)
                if self.type == "freq":
                        print(self.label or self.raw_spec)
                        print("\t%-10s %s" % ("COUNT", "EVENT"))
                        data = sorted(data.items(), key=lambda kv: kv[1].value)
                        if top is not None:
                                data = data[-top:]
                        for key, value in data:
                                # Print some nice values if the user didn't
                                # specify an expression to probe
                                if self.is_default_expr:
                                        if not self.probe_type == "r":
                                                key_str = "total calls"
                                        else:
                                                key_str = "retval = %s" % \
                                                          self._v2s(key.v0)
                                else:
                                        key_str = self._display_key(key)
                                print("\t%-10s %s" % \
                                      (str(value.value), key_str))
                elif self.type == "hist":
                        label = self.label or (self._display_expr(0)
                                if not self.is_default_expr  else "retval")
                        data.print_log2_hist(val_type=label)

        def __str__(self):
                return self.label or self.raw_spec

class Tool(object):
        examples = """
Probe specifier syntax:
        {p,r,t,u}:{[library],category}:function(signature)[:type[,type...]:expr[,expr...][:filter]][#label]
Where:
        p,r,t,u    -- probe at function entry, function exit, kernel tracepoint,
                      or USDT probe
                      in exit probes: can use $retval, $entry(param), $latency
        library    -- the library that contains the function
                      (leave empty for kernel functions)
        category   -- the category of the kernel tracepoint (e.g. net, sched)
        function   -- the function name to trace (or tracepoint name)
        signature  -- the function's parameters, as in the C header
        type       -- the type of the expression to collect (supports multiple)
        expr       -- the expression to collect (supports multiple)
        filter     -- the filter that is applied to collected values
        label      -- the label for this probe in the resulting output

EXAMPLES:

argdist -H 'p::__kmalloc(u64 size):u64:size'
        Print a histogram of allocation sizes passed to kmalloc

argdist -p 1005 -C 'p:c:malloc(size_t size):size_t:size:size==16'
        Print a frequency count of how many times process 1005 called malloc
        with an allocation size of 16 bytes

argdist -C 'r:c:gets():char*:(char*)$retval#snooped strings'
        Snoop on all strings returned by gets()

argdist -H 'r::__kmalloc(size_t size):u64:$latency/$entry(size)#ns per byte'
        Print a histogram of nanoseconds per byte from kmalloc allocations

argdist -C 'p::__kmalloc(size_t size, gfp_t flags):size_t:size:flags&GFP_ATOMIC'
        Print frequency count of kmalloc allocation sizes that have GFP_ATOMIC

argdist -p 1005 -C 'p:c:write(int fd):int:fd' -T 5
        Print frequency counts of how many times writes were issued to a
        particular file descriptor number, in process 1005, but only show
        the top 5 busiest fds

argdist -p 1005 -H 'r:c:read()'
        Print a histogram of results (sizes) returned by read() in process 1005

argdist -C 'r::__vfs_read():u32:$PID:$latency > 100000'
        Print frequency of reads by process where the latency was >0.1ms

argdist -H 'r::__vfs_read(void *file, void *buf, size_t count):size_t:$entry(count):$latency > 1000000'
        Print a histogram of read sizes that were longer than 1ms

argdist -H \\
        'p:c:write(int fd, const void *buf, size_t count):size_t:count:fd==1'
        Print a histogram of buffer sizes passed to write() across all
        processes, where the file descriptor was 1 (STDOUT)

argdist -C 'p:c:fork()#fork calls'
        Count fork() calls in libc across all processes
        Can also use funccount.py, which is easier and more flexible

argdist -H 't:block:block_rq_complete():u32:tp.nr_sector'
        Print histogram of number of sectors in completing block I/O requests

argdist -C 't:irq:irq_handler_entry():int:tp.irq'
        Aggregate interrupts by interrupt request (IRQ)

argdist -C 'u:pthread:pthread_start():u64:arg2' -p 1337
        Print frequency of function addresses used as a pthread start function,
        relying on the USDT pthread_start probe in process 1337

argdist  -H \\
        'p:c:sleep(u32 seconds):u32:seconds' \\
        'p:c:nanosleep(struct timespec *req):long:req->tv_nsec'
        Print histograms of sleep() and nanosleep() parameter values

argdist -p 2780 -z 120 \\
        -C 'p:c:write(int fd, char* buf, size_t len):char*:buf:fd==1'
        Spy on writes to STDOUT performed by process 2780, up to a string size
        of 120 characters
"""

        def __init__(self):
                parser = argparse.ArgumentParser(description="Trace a " +
                  "function and display a summary of its parameter values.",
                  formatter_class=argparse.RawDescriptionHelpFormatter,
                  epilog=Tool.examples)
                parser.add_argument("-p", "--pid", type=int,
                  help="id of the process to trace (optional)")
                parser.add_argument("-z", "--string-size", default=80,
                  type=int,
                  help="maximum string size to read from char* arguments")
                parser.add_argument("-i", "--interval", default=1, type=int,
                  help="output interval, in seconds")
                parser.add_argument("-n", "--number", type=int, dest="count",
                  help="number of outputs")
                parser.add_argument("-v", "--verbose", action="store_true",
                  help="print resulting BPF program code before executing")
                parser.add_argument("-T", "--top", type=int,
                  help="number of top results to show (not applicable to " +
                  "histograms)")
                parser.add_argument("-H", "--histogram", nargs="*",
                  dest="histspecifier", metavar="specifier",
                  help="probe specifier to capture histogram of " +
                  "(see examples below)")
                parser.add_argument("-C", "--count", nargs="*",
                  dest="countspecifier", metavar="specifier",
                  help="probe specifier to capture count of " +
                  "(see examples below)")
                parser.add_argument("-I", "--include", nargs="*",
                  metavar="header",
                  help="additional header files to include in the BPF program")
                self.args = parser.parse_args()
                self.usdt_ctx = None

        def _create_probes(self):
                self.probes = []
                for specifier in (self.args.countspecifier or []):
                        self.probes.append(Probe(self, "freq", specifier))
                for histspecifier in (self.args.histspecifier or []):
                        self.probes.append(Probe(self, "hist", histspecifier))
                if len(self.probes) == 0:
                        print("at least one specifier is required")
                        exit()

        def enable_usdt_probe(self, probe_name, fn_name):
                if not self.usdt_ctx:
                        self.usdt_ctx = USDT(pid=self.args.pid)
                self.usdt_ctx.enable_probe(probe_name, fn_name)

        def _generate_program(self):
                bpf_source = """
struct __string_t { char s[%d]; };

#include <uapi/linux/ptrace.h>
                """ % self.args.string_size
                for include in (self.args.include or []):
                        bpf_source += "#include <%s>\n" % include
                bpf_source += BPF.generate_auto_includes(
                                map(lambda p: p.raw_spec, self.probes))
                bpf_source += Tracepoint.generate_decl()
                bpf_source += Tracepoint.generate_entry_probe()
                for probe in self.probes:
                        bpf_source += probe.generate_text()
                if self.args.verbose:
                        if self.usdt_ctx: print(self.usdt_ctx.get_text())
                        print(bpf_source)
                self.bpf = BPF(text=bpf_source, usdt=self.usdt_ctx)

        def _attach(self):
                Tracepoint.attach(self.bpf)
                for probe in self.probes:
                        probe.attach(self.bpf)
                if self.args.verbose:
                        print("open uprobes: %s" % self.bpf.open_uprobes)
                        print("open kprobes: %s" % self.bpf.open_kprobes)

        def _main_loop(self):
                count_so_far = 0
                while True:
                        try:
                                sleep(self.args.interval)
                        except KeyboardInterrupt:
                                exit()
                        print("[%s]" % strftime("%H:%M:%S"))
                        for probe in self.probes:
                                probe.display(self.args.top)
                        count_so_far += 1
                        if self.args.count is not None and \
                           count_so_far >= self.args.count:
                                exit()

        def _close_probes(self):
                for probe in self.probes:
                        probe.close()
                        if self.args.verbose:
                                print("closed probe: " + str(probe))

        def run(self):
                try:
                        self._create_probes()
                        self._generate_program()
                        self._attach()
                        self._main_loop()
                except:
                        if self.args.verbose:
                                traceback.print_exc()
                        elif sys.exc_info()[0] is not SystemExit:
                                print(sys.exc_info()[1])
                self._close_probes()

if __name__ == "__main__":
        Tool().run()

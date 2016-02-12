#!/usr/bin/env python
#
# argdist.py   Trace a function and display a distribution of its
#              parameter values as a histogram or frequency count.
#
# USAGE: argdist.py [-h] [-p PID] [-z STRING_SIZE] [-i INTERVAL]
#                   [-n COUNT] [-C specifier [specifier ...]]
#                   [-H specifier [specifier ...]]
#
# Licensed under the Apache License, Version 2.0 (the "License")
# Copyright (C) 2016 Sasha Goldshtein.

from bcc import BPF
from time import sleep, strftime
import argparse

class Specifier(object):
        text = """
DATA_DECL

int PROBENAME(struct pt_regs *ctx SIGNATURE)
{
        PID_FILTER
        KEY_EXPR
        if (!(FILTER)) return 0;
        COLLECT
        return 0;
}
"""
        next_probe_index = 0

        def __init__(self, type, specifier, pid):
                self.raw_spec = specifier 
                spec_and_label = specifier.split(';')
                self.label = spec_and_label[1] \
                             if len(spec_and_label) == 2 else None
                parts = spec_and_label[0].strip().split(':')
                if len(parts) < 3 or len(parts) > 6:
                        raise ValueError("invalid specifier format")
                self.type = type    # hist or freq
                self.is_ret_probe = parts[0] == "r"
                if self.type != "hist" and self.type != "freq":
                        raise ValueError("unrecognized probe type")
                if parts[0] not in ["r", "p"]:
                        raise ValueError("unrecognized probe type")
                self.library = parts[1]
                self.is_user = len(self.library) > 0
                fparts = parts[2].split('(')
                if len(fparts) != 2:
                        raise ValueError("invalid specifier format")
                self.function = fparts[0]
                self.signature = fparts[1][:-1]
                self.is_default_expr = len(parts) < 5
                if not self.is_default_expr:
                        self.expr_type = parts[3]
                        self.expr = parts[4]
                else:
                        if not self.is_ret_probe and self.type == "hist":
                                raise ValueError("dist probes must have expr")
                        self.expr_type = \
                                "u64" if not self.is_ret_probe else "int"
                        self.expr = "1" if not self.is_ret_probe else "$retval"
                self.expr = self.expr.replace("$retval",
                                              "(%s)ctx->ax" % self.expr_type)
                self.filter = None if len(parts) != 6 else parts[5]
                if self.filter is not None:
                        self.filter = self.filter.replace("$retval",
                                "(%s)ctx->ax" % self.expr_type)
                self.pid = pid
                self.probe_func_name = "%s_probe%d" % \
                        (self.function, Specifier.next_probe_index)
                self.probe_hash_name = "%s_hash%d" % \
                        (self.function, Specifier.next_probe_index)
                Specifier.next_probe_index += 1

        def _is_string_probe(self):
                return self.expr_type == "char*" or self.expr_type == "char *"

        def generate_text(self, string_size):
                program = self.text.replace("PROBENAME", self.probe_func_name)
                signature = "" if len(self.signature) == 0 \
                               else "," + self.signature
                program = program.replace("SIGNATURE", signature)
                if self.pid is not None and not self.is_user:
                        # kernel probes need to explicitly filter pid
                        program = program.replace("PID_FILTER",
                                "u32 pid = bpf_get_current_pid_tgid();\n" + \
                                "if (pid != %d) { return 0; }" % self.pid)
                else:
                        program = program.replace("PID_FILTER", "")
                if self._is_string_probe():
                        decl = """
struct %s_key_t { char key[%d]; };
BPF_HASH(%s, struct %s_key_t, u64);
""" \
                        % (self.function, string_size,
                           self.probe_hash_name, self.function)
                        collect = "%s.increment(__key);" % self.probe_hash_name
                        key_expr = """
struct %s_key_t __key = {0};
bpf_probe_read(&__key.key, sizeof(__key.key), %s);
""" \
                        % (self.function, self.expr)
                elif self.type == "freq":
                        decl = "BPF_HASH(%s, %s, u64);" % \
                                (self.probe_hash_name, self.expr_type)
                        collect = "%s.increment(__key);" % self.probe_hash_name
                        key_expr = "%s __key = %s;" % \
                                   (self.expr_type, self.expr)
                elif self.type == "hist":
                        decl = "BPF_HISTOGRAM(%s, %s);" % \
                                (self.probe_hash_name, self.expr_type)
                        collect = "%s.increment(bpf_log2l(__key));" % \
                                  self.probe_hash_name 
                        key_expr = "%s __key = %s;" % \
                                   (self.expr_type, self.expr)
                program = program.replace("DATA_DECL", decl)
                program = program.replace("KEY_EXPR", key_expr) 
                program = program.replace("FILTER", self.filter or "1") 
                program = program.replace("COLLECT", collect)
                return program

        def attach(self, bpf):
                self.bpf = bpf
                if self.is_user:
                        if self.is_ret_probe:
                                bpf.attach_uretprobe(name=self.library,
                                                  sym=self.function,
                                                  fn_name=self.probe_func_name,
                                                  pid=self.pid or -1)
                        else:
                                bpf.attach_uprobe(name=self.library,
                                                  sym=self.function,
                                                  fn_name=self.probe_func_name,
                                                  pid=self.pid or -1)
                else:
                        if self.is_ret_probe:
                                bpf.attach_kretprobe(event=self.function,
                                                  fn_name=self.probe_func_name)
                        else:
                                bpf.attach_kprobe(event=self.function,
                                                  fn_name=self.probe_func_name)

        def display(self):
                print(self.label or self.raw_spec)
                data = self.bpf.get_table(self.probe_hash_name)
                if self.type == "freq":
                        print("\t%-10s %s" % ("COUNT", "EVENT"))
                        for key, value in sorted(data.items(),
                                                 key=lambda kv: kv[1].value):
                                key_val = key.key if self._is_string_probe() \
                                                  else str(key.value)
                                if self.is_default_expr:
                                        if not self.is_ret_probe:
                                                key_str = "total calls"
                                        else:
                                                key_str = "retval = %s" % \
                                                          key_val
                                else:
                                        key_str = "%s = %s" % \
                                                  (self.expr, key_val)
                                print("\t%-10s %s" % \
                                      (str(value.value), key_str))
                elif self.type == "hist":
                        label = self.expr if not self.is_default_expr \
                                          else "retval"
                        data.print_log2_hist(val_type=label)

examples = """
Probe specifier syntax:
        {p,r}:[library]:function(signature)[:type:expr[:filter]][;label]
Where:
        p,r        -- probe at function entry or at function exit
                      in exit probes, only $retval is accessible
        library    -- the library that contains the function
                      (leave empty for kernel functions)
        function   -- the function name to trace
        signature  -- the function's parameters, as in the C header
        type       -- the type of the expression to collect
        expr       -- the expression to collect
        filter     -- the filter that is applied to collected values
        label      -- the label for this probe in the resulting output

EXAMPLES:

argdist.py -H 'p::__kmalloc(u64 size):u64:size'
        Print a histogram of allocation sizes passed to kmalloc

argdist.py -p 1005 -C 'p:c:malloc(size_t size):size_t:size:size==16'
        Print a frequency count of how many times process 1005 called malloc
        with an allocation size of 16 bytes

argdist.py -C 'r:c:gets():char*:$retval;snooped strings'
        Snoop on all strings returned by gets()

argdist.py -p 1005 -C 'p:c:write(int fd):int:fd'
        Print frequency counts of how many times writes were issued to a
        particular file descriptor number, in process 1005

argdist.py -p 1005 -H 'r:c:read()'
        Print a histogram of error codes returned by read() in process 1005

argdist.py -H \\
        'p:c:write(int fd, const void *buf, size_t count):size_t:count:fd==1'
        Print a histogram of buffer sizes passed to write() across all
        processes, where the file descriptor was 1 (STDOUT)

argdist.py -C 'p:c:fork();fork calls'
        Count fork() calls in libc across all processes
        Can also use funccount.py, which is easier and more flexible 

argdist.py \\
        -H 'p:c:sleep(u32 seconds):u32:seconds' \\
        -H 'p:c:nanosleep(struct timespec { time_t tv_sec; long tv_nsec; } *req):long:req->tv_nsec'
        Print histograms of sleep() and nanosleep() parameter values

argdist.py -p 2780 -z 120 \\
        -C 'p:c:write(int fd, char* buf, size_t len):char*:buf:fd==1'
        Spy on writes to STDOUT performed by process 2780, up to a string size
        of 120 characters 
"""

parser = argparse.ArgumentParser(description=
        "Trace a function and display a summary of its parameter values.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
parser.add_argument("-p", "--pid", type=int,
        help="id of the process to trace (optional)")
parser.add_argument("-z", "--string-size", default=80, type=int,
        help="maximum string size to read from char* arguments")
parser.add_argument("-i", "--interval", default=1, type=int,
        help="output interval, in seconds")
parser.add_argument("-n", "--number", type=int, dest="count",
        help="number of outputs")
parser.add_argument("-H", "--histogram", nargs="*", dest="histspecifier",
        help="probe specifier to capture histogram of (see examples below)")
parser.add_argument("-C", "--count", nargs="*", dest="countspecifier",
        help="probe specifier to capture count of (see examples below)")
parser.add_argument("-v", "--verbose", action="store_true",
        help="print resulting BPF program code before executing")
args = parser.parse_args()

specifiers = []
for specifier in (args.countspecifier or []):
        specifiers.append(Specifier("freq", specifier, args.pid))
for histspecifier in (args.histspecifier or []):
        specifiers.append(Specifier("hist", histspecifier, args.pid))
if len(specifiers) == 0:
        print("at least one specifier is required")
        exit(1)

bpf_source = "#include <uapi/linux/ptrace.h>\n"
for specifier in specifiers:
        bpf_source += specifier.generate_text(args.string_size)

if args.verbose:
        print(bpf_source)

bpf = BPF(text=bpf_source)

for specifier in specifiers:
        specifier.attach(bpf)

count_so_far = 0
while True:
        try:
                sleep(args.interval)
        except KeyboardInterrupt:
                exit()
        print("[%s]" % strftime("%H:%M:%S"))
        for specifier in specifiers:
                specifier.display()
        count_so_far += 1
        if args.count is not None and count_so_far >= args.count:
                exit()

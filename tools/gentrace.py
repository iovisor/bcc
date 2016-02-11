#!/usr/bin/env python
#
# gentrace.py   Trace a function and display a histogram or summary of its
#               parameter values. 
#
# USAGE: gentrace.py [-h] [-p PID] [-z STRING_SIZE]
#                    [-s SPECIFIER [SPECIFIER ...]]
#                    [interval] [count]
#
# Copyright (C) 2016 Sasha Goldshtein.

from bcc import BPF
from time import sleep, strftime
import argparse

class Specifier(object):
        text = """
DATA_DECL

int PROBENAME(struct pt_regs *ctx SIGNATURE)
{
        KEY_EXPR
        if (!(FILTER)) return 0;
        COLLECT
        return 0;
}
"""

        # <raw|hist>:lib:function(signature)[:type:expr[:filter]]
        def __init__(self, specifier, pid):
                self.raw_spec = specifier 
                parts = specifier.strip().split(':')
                if len(parts) < 3 or len(parts) > 6:
                        raise ValueError("invalid specifier format")
                self.type = parts[0]    # hist or raw
                self.is_ret_probe = self.type.endswith("-ret")
                if self.is_ret_probe:
                        self.type = self.type[:-len("-ret")]
                if self.type != "hist" and self.type != "raw":
                        raise ValueError("unrecognized probe type")
                self.library = parts[1]
                fparts = parts[2].split('(')
                if len(fparts) != 2:
                        raise ValueError("invalid specifier format")
                self.function = fparts[0]
                self.signature = fparts[1][:-1]
                if len(parts) >= 5:
                        self.expr_type = parts[3]
                        self.expr = parts[4]
                else:
                        self.expr_type = \
                                "u64" if not self.is_ret_probe else "int"
                        self.expr = "1" if not self.is_ret_probe else "@retval"
                self.expr = self.expr.replace("@retval",
                                              "(%s)ctx->ax" % self.expr_type)
                self.filter = None if len(parts) != 6 else parts[5]
                self.pid = pid
                self.probe_func_name = self.function + "_probe"
                self.probe_hash_name = self.function + "_hash"

        def _is_string_probe(self):
                return self.expr_type == "char*" or self.expr_type == "char *"

        def generate_text(self, string_size):
                program = self.text.replace("PROBENAME", self.probe_func_name)
                signature = "" if len(self.signature) == 0 \
                               else "," + self.signature
                program = program.replace("SIGNATURE", signature)
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
                elif self.type == "raw":
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
                if len(self.library) > 0:
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
                print(self.raw_spec)
                data = self.bpf.get_table(self.probe_hash_name)
                if self.type == "raw":
                        print("\t%-10s %s" % ("COUNT", "EVENT"))
                        for key, value in sorted(data.items(),
                                                 key=lambda kv: kv[1].value):
                                if self._is_string_probe():
                                        key_str = key.key
                                else:
                                        key_str = str(key.value)
                                print("\t%-10s %s = %s" %
                                      (str(value.value), self.expr, key_str))
                elif self.type == "hist":
                        data.print_log2_hist(val_type=self.expr)

examples = """
Probe specifier syntax:
        <raw|hist>[-ret]:[library]:function(signature)[:type:expr[:filter]]
Where:
        <raw|hist> -- collect raw data or a histogram of values
        ret        -- probe at function exit, only @retval is accessible
        library    -- the library that contains the function
                      (leave empty for kernel functions)
        function   -- the function name to trace
        signature  -- the function's parameters, as in the C header
        type       -- the type of the expression to collect
        expr       -- the expression to collect
        filter     -- a filter that is applied to collected values

EXAMPLES:

gentrace.py -s "hist::__kmalloc(u64 size):u64:size"
        Print a histogram of allocation sizes passed to kmalloc

gentrace.py -p 1005 -s "raw:c:malloc(size_t size):size_t:size:size==16"
        Print a raw count of how many times process 1005 called malloc with
        an allocation size of 16 bytes

gentrace.py -s "raw-ret:c:gets():char*:@retval"
        Snoop on all strings returned by gets()

gentrace.py -p 1005 -s "raw:c:write(int fd):int:fd"
        Print raw counts of how many times writes were issued to a particular
        file descriptor number, in process 1005

gentrace.py -p 1005 -s "hist-ret:c:read()"
        Print a histogram of error codes returned by read() in process 1005

gentrace.py -s "hist:c:write(int fd, const void *buf, size_t count):size_t:count:fd==1"
        Print a histogram of buffer sizes passed to write() across all
        processes, where the file descriptor was 1 (STDOUT)

gentrace.py -s "raw:c:fork"
        Count fork() calls in libc across all processes
        Can also use funccount.py, which is easier and more flexible 

gentrace.py -s \\
        "hist:c:sleep(u32 seconds):u32:seconds" \\
        "hist:c:nanosleep(struct timespec { time_t tv_sec; long tv_nsec; } *req):long:req->tv_nsec"
        Print histograms of sleep() and nanosleep() parameter values

gentrace.py -p 2780 -s -z 120 "raw:c:write(int fd, char* buf, size_t len):char*:buf:fd==1"
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
parser.add_argument("interval", nargs="?", default=1, type=int,
        help="output interval, in seconds")
parser.add_argument("count", nargs="?", type=int,
        help="number of outputs")
parser.add_argument("-s", "--specifier", nargs="+", dest="specifiers",
        help="the probe specifiers (see examples below)")
args = parser.parse_args()

specifiers = []
for specifier in args.specifiers:
        specifiers.append(Specifier(specifier, args.pid))

bpf_source = "#include <uapi/linux/ptrace.h>\n"
for specifier in specifiers:
        bpf_source += specifier.generate_text(args.string_size)

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

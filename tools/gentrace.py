#!/usr/bin/env python
#
# gentrace.py   Trace a function and display a histogram or summary of its
#               parameter values. 
#
# USAGE: TODO
#
# Copyright (C) 2016 Sasha Goldshtein.

from bcc import BPF
from time import sleep
import argparse

class Specifier(object):
        text = """
DATA_DECL

int PROBENAME(struct pt_regs *ctx, SIGNATURE)
{
        EXPR_TYPE __key = EXPR;
        COLLECT
        return 0;
}
"""
        def __init__(self, specifier, library):
                parts = specifier.strip().split(':')
                if len(parts) < 4 or len(parts) > 5:
                        raise ValueError("invalid specifier format")
                self.type = parts[0]    # hist or raw
                if self.type != "hist" and self.type != "raw":
                        raise ValueError("unrecognized probe type")
                fparts = parts[1].split('(')
                if len(fparts) != 2:
                        raise ValueError("invalid specifier format")
                self.function = fparts[0]
                self.signature = fparts[1][:-1]
                self.expr_type = parts[2]
                self.expr = parts[3]
                self.filter = None if len(parts) != 5 else parts[4]
                self.library = library
                self.probe_func_name = self.function + "_probe"
                self.probe_hash_name = self.function + "_hash"
        def generate_text(self):
                # TODO Need special treatment of strings (char *) expressions
                program = self.text.replace("PROBENAME", self.probe_func_name)
                program = program.replace("SIGNATURE", self.signature)
                if self.type == "raw":
                        decl = "BPF_HASH(%s, %s, u64);" % \
                                (self.probe_hash_name, self.expr_type)
                        collect = "u64 zero = 0, *val; val = %s.lookup_or_init(&__key, &zero); (*val)++;" % self.probe_hash_name
                elif self.type == "hist":
                        pass    # TODO
                program = program.replace("DATA_DECL", decl)
                program = program.replace("EXPR_TYPE", self.expr_type)
                program = program.replace("EXPR", self.expr)
                program = program.replace("COLLECT", collect)
                return program
        def attach(self, bpf):
                self.bpf = bpf
                if self.library is not None:
                        bpf.attach_uprobe(name=self.library,
                                          sym=self.function,
                                          fn_name=self.probe_func_name)
                else:
                        bpf.attach_kprobe(event=self.function,
                                          fn_name=self.probe_func_name)
        def display(self):
                data = self.bpf.get_table(self.probe_hash_name)
                if self.type == "raw":
                        for key, value in sorted(data.items(), key=lambda kv: kv[1].value):
                                print("%20s = %-20s count = %s" % (self.expr, str(key.value), str(value.value)))
                elif self.type == "hist":
                        pass    # TODO

examples = """
EXAMPLES:
        TODO
"""

# probe specifier syntax:
#       <hist|raw>:<function name>(<signature>):<type>:<expr>[:filter]
#       hist:malloc(size_t size):size_t:size:size>16
#       hist:fwrite(FILE* f, size_t count):size_t:count
#       raw:printf(char * format):char:format[0]
#       hist:fwrite(FILE* file):int:file->fd:file->fd==2

parser = argparse.ArgumentParser(description=
        "Trace a function and display a summary of its parameter values.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
parser.add_argument("-l", "--library",
        help="the library which contains the function to trace")
parser.add_argument("-s", "--specifier", nargs="+", dest="specifiers",
        help="the probe specifier")
parser.add_argument("interval", nargs="?", default=1,
        help="output interval, in seconds")
parser.add_argument("count", nargs="?",
        help="number of outputs")
args = parser.parse_args()

specifiers = []
for specifier in args.specifiers:
        specifiers.append(Specifier(specifier, args.library))

bpf_source = "#include <uapi/linux/ptrace.h>\n"
for specifier in specifiers:
        bpf_source += specifier.generate_text()

bpf = BPF(text=bpf_source)

for specifier in specifiers:
        specifier.attach(bpf)

while True:
        print("COLLECTED DATA:")
        for specifier in specifiers:
                specifier.display()
        sleep(args.interval)

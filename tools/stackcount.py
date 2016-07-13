#!/usr/bin/env python
#
# stackcount    Count function calls and their stack traces.
#               For Linux, uses BCC, eBPF.
#
# USAGE: stackcount [-h] [-p PID] [-i INTERVAL] [-T] [-r] [-s]
#                   [-v] pattern
#
# The pattern is a string with optional '*' wildcards, similar to file
# globbing. If you'd prefer to use regular expressions, use the -r option.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 12-Jan-2016	Brendan Gregg	    Created this.
# 09-Jul-2016   Sasha Goldshtein    Added user-space function support.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import signal
import traceback
import sys

class Probe(object):
    def __init__(self, pattern, use_regex):
        """Init a new probe.

        Init the probe from the pattern provided by the user. The supported
        patterns mimic the 'trace' and 'argdist' tools, but are simpler because
        we don't have to distinguish between probes and retprobes.

            func            -- probe a kernel function
            lib:func        -- probe a user-space function in the library 'lib'
            t:cat:event     -- probe a kernel tracepoint
            u:lib:event     -- probe a user-space USDT tracepoint
        """
        parts = pattern.split(':')
        if len(parts) == 1:
            parts = ["f", "", parts[0]]
        elif len(parts) == 2:
            parts = ["f", parts[0], parts[1]]
        elif len(parts) == 3:
            if parts[0] == "t":
                parts = ["t", "", "%s:%s" % tuple(parts[1:])]
            if parts[0] not in ["f", "t", "u"]:
                raise Exception("Type must be 'f', 't', or 'u', but got %s" %
                                parts[0])
        else:
            raise Exception("Too many ':'-separated components in pattern %s" %
                            pattern)

        (self.type, self.library, self.pattern) = parts
        if not use_regex:
            self.pattern = self.pattern.replace('*', '.*')
            self.pattern = '^' + self.pattern + '$'

        if self.type == "f" and self.library:
            self.library = BPF.find_library(self.library)

    def is_kernel_probe(self):
        return self.type == "t" or (self.type == "f" and self.library == "")

    def attach(self, bpf, fn_name):
        if self.type == "f":
            if self.library:
                bpf.attach_uprobe(name=self.library, sym_re=self.pattern,
                                  fn_name=fn_name)
                self.matched = bpf.num_open_uprobes()
            else:
                bpf.attach_kprobe(event_re=pattern, fn_name=fn_name)
                self.matched = bpf.num_open_kprobes()
        elif self.type == "t":
            bpf.attach_tracepoint(tp_re=self.pattern, fn_name=fn_name)
            self.matched = bpf.num_open_tracepoints()
        elif self.type == "u":
            # TODO
            raise Exception("USDT probes are not yet supported")

        if self.matched == 0:
            raise Exception("No functions matched by pattern %s" % self.pattern)

class Tool(object):
    def __init__(self):
        examples = """examples:
    ./stackcount submit_bio          # count kernel stack traces for submit_bio
    ./stackcount ip_output           # count kernel stack traces for ip_output
    ./stackcount -s ip_output        # show symbol offsets
    ./stackcount -sv ip_output       # show offsets and raw addresses (verbose)
    ./stackcount 'tcp_send*'         # count stacks for funcs matching tcp_send*
    ./stackcount -r '^tcp_send.*'    # same as above, using regular expressions
    ./stackcount -Ti 5 ip_output     # output every 5 seconds, with timestamps
    ./stackcount -p 185 ip_output    # count ip_output stacks for PID 185 only
    ./stackcount -p 185 -l c malloc  # count stacks for malloc in PID 185
        """
        parser = argparse.ArgumentParser(
            description="Count function calls and their stack traces",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=examples)
        parser.add_argument("-p", "--pid", type=int,
            help="trace this PID only")
        parser.add_argument("-i", "--interval", default=99999999,
            help="summary interval, seconds")
        parser.add_argument("-T", "--timestamp", action="store_true",
            help="include timestamp on output")
        parser.add_argument("-r", "--regexp", action="store_true",
            help="use regular expressions. Default is \"*\" wildcards only.")
        parser.add_argument("-s", "--offset", action="store_true",
            help="show address offsets")
        parser.add_argument("-v", "--verbose", action="store_true",
            help="show raw addresses")
        parser.add_argument("pattern",
            help="search expression for functions")
        self.args = parser.parse_args()
        self.probe = Probe(self.args.pattern, self.args.regexp)
        if not self.args.pid and not self.probe.is_kernel_probe():
            raise Exception("pid must be specified when tracing user-space")

    def load(self):
        bpf_text = """#include <uapi/linux/ptrace.h>

        BPF_HASH(counts, int);
        BPF_STACK_TRACE(stack_traces, 1024);

        int trace_count(void *ctx) {
            FILTER
            int key = stack_traces.get_stackid(ctx, STACK_FLAGS);
            u64 zero = 0;
            u64 *val = counts.lookup_or_init(&key, &zero);
            (*val)++;
            return 0;
        }
        """

        # We really mean the tgid from the kernel's perspective, which is in
        # the top 32 bits of bpf_get_current_pid_tgid().
        if self.args.pid:
            bpf_text = bpf_text.replace('FILTER',
                ('u32 pid; pid = bpf_get_current_pid_tgid() >> 32; ' +
                'if (pid != %d) { return 0; }') % (self.args.pid))
        else:
            bpf_text = bpf_text.replace('FILTER', '')

        stack_flags = 'BPF_F_REUSE_STACKID'
        if not self.probe.is_kernel_probe():
            stack_flags += '| BPF_F_USER_STACK'
        bpf_text = bpf_text.replace('STACK_FLAGS', stack_flags)

        self.bpf = BPF(text=bpf_text)

    def _print_frame(self, addr):
        print("  ", end="")
        if self.args.verbose:
            print("%-16x " % addr, end="")
        if self.args.offset:
            print("%s" % self.bpf.symaddr(addr, self.args.pid or -1))
        else:
            print("%s" % self.bpf.sym(addr, self.args.pid or -1))

    @staticmethod
    def _signal_ignore(signal, frame):
        print()

    def run(self):
        self.probe.attach(self.bpf, fn_name="trace_count")
        print("Tracing %d functions for \"%s\"... Hit Ctrl-C to end." %
              (self.probe.matched, self.args.pattern))
        exiting = 0 if self.args.interval else 1
        while True:
            try:
                sleep(int(self.args.interval))
            except KeyboardInterrupt:
                exiting = 1
                # as cleanup can take many seconds, trap Ctrl-C:
                signal.signal(signal.SIGINT, Tool._signal_ignore)

            print()
            if self.args.timestamp:
                print("%-8s\n" % strftime("%H:%M:%S"), end="")

            counts = self.bpf["counts"]
            stack_traces = self.bpf["stack_traces"]
            for k, v in sorted(counts.items(),
                               key=lambda counts: counts[1].value):
                for addr in stack_traces.walk(k.value):
                    self._print_frame(addr)
                print("    %d\n" % v.value)
            counts.clear()

            if exiting:
                print("Detaching...")
                exit()

if __name__ == "__main__":
    try:
        tool = Tool()
        tool.load()
        tool.run()
    except Exception:
        traceback.print_exc() # TODO print this only in -DEBUG mode


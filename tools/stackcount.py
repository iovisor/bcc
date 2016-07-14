#!/usr/bin/env python
#
# stackcount    Count events and their stack traces.
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
# 09-Jul-2016   Sasha Goldshtein    Generalized for uprobes and tracepoints.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import signal
import traceback
import sys

debug = True

class Probe(object):
    def __init__(self, pattern, use_regex, pid):
        """Init a new probe.

        Init the probe from the pattern provided by the user. The supported
        patterns mimic the 'trace' and 'argdist' tools, but are simpler because
        we don't have to distinguish between probes and retprobes.

            func            -- probe a kernel function
            lib:func        -- probe a user-space function in the library 'lib'
            p::func         -- same thing as 'func'
            p:lib:func      -- same thing as 'lib:func'
            t:cat:event     -- probe a kernel tracepoint
        """
        parts = pattern.split(':')
        if len(parts) == 1:
            parts = ["p", "", parts[0]]
        elif len(parts) == 2:
            parts = ["p", parts[0], parts[1]]
        elif len(parts) == 3:
            if parts[0] == "t":
                parts = ["t", "", "%s:%s" % tuple(parts[1:])]
            if parts[0] not in ["p", "t"]:
                raise Exception("Type must be 'p' or 't', but got %s" %
                                parts[0])
        else:
            raise Exception("Too many ':'-separated components in pattern %s" %
                            pattern)

        (self.type, self.library, self.pattern) = parts
        if not use_regex:
            self.pattern = self.pattern.replace('*', '.*')
            self.pattern = '^' + self.pattern + '$'

        if self.type == "p" and self.library:
            self.library = BPF.find_library(self.library)

        self.pid = pid
        # TODO Remove this limitation, which is only there because we need the
        # pid to resolve symbols. If we maintain a stack cache per pid, we can
        # resolve the right symbols on the fly. We will need to merge the stacks
        # in user-space, however -- we could have the same functions called with
        # the same stacks across multiple processes. Maybe print the pids in
        # that case, or make it an option to join pids or print each pid's stack
        # separately.
        if not self.pid and not self.is_kernel_probe():
            raise Exception("pid must be specified when tracing user-space")

    def is_kernel_probe(self):
        return self.type == "t" or (self.type == "p" and self.library == "")

    def attach(self):
        if self.type == "p":
            if self.library:
                self.bpf.attach_uprobe(name=self.library, sym_re=self.pattern,
                                       fn_name="trace_count", pid=self.pid)
                self.matched = self.bpf.num_open_uprobes()
            else:
                self.bpf.attach_kprobe(event_re=pattern, fn_name="trace_count",
                                       pid=self.pid)
                self.matched = self.bpf.num_open_kprobes()
        elif self.type == "t":
            self.bpf.attach_tracepoint(tp_re=self.pattern,
                                       fn_name="trace_count", pid=self.pid)
            self.matched = self.bpf.num_open_tracepoints()

        if self.matched == 0:
            raise Exception("No functions matched by pattern %s" % self.pattern)

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
        # TODO Why do we even need this when we call attach_nnn with the pid,
        # which eventually calls perf_event_open with that pid? Is it ignored?
        # It works for uprobes, why not for kprobes/tracepoints?
        if self.is_kernel_probe() and self.pid:
            bpf_text = bpf_text.replace('FILTER',
                ('u32 pid; pid = bpf_get_current_pid_tgid() >> 32; ' +
                'if (pid != %d) { return 0; }') % (self.pid))
        else:
            bpf_text = bpf_text.replace('FILTER', '')

        stack_flags = 'BPF_F_REUSE_STACKID'
        if not self.is_kernel_probe():
            stack_flags += '| BPF_F_USER_STACK' # can't do both U *and* K
        bpf_text = bpf_text.replace('STACK_FLAGS', stack_flags)

        if debug:
            print(bpf_text)
        self.bpf = BPF(text=bpf_text)

class Tool(object):
    def __init__(self):
        examples = """examples:
    ./stackcount submit_bio          # count kernel stack traces for submit_bio
    ./stackcount -s ip_output        # show symbol offsets
    ./stackcount -sv ip_output       # show offsets and raw addresses (verbose)
    ./stackcount 'tcp_send*'         # count stacks for funcs matching tcp_send*
    ./stackcount -r '^tcp_send.*'    # same as above, using regular expressions
    ./stackcount -Ti 5 ip_output     # output every 5 seconds, with timestamps
    ./stackcount -p 185 ip_output    # count ip_output stacks for PID 185 only
    ./stackcount -p 185 c:malloc     # count stacks for malloc in PID 185
    ./stackcount t:sched:sched_fork  # count stacks for the sched_fork tracepoint
    ./stackcount -p 185 u:node:*     # count stacks for all USDT probes in node
        """
        parser = argparse.ArgumentParser(
            description="Count events and their stack traces",
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
            help="search expression for events")
        self.args = parser.parse_args()
        self.probe = Probe(self.args.pattern, self.args.regexp, self.args.pid)

    def _print_frame(self, addr):
        pid_for_syms = None if self.probe.is_kernel_probe() else self.args.pid
        print("  ", end="")
        if self.args.verbose:
            print("%-16x " % addr, end="")
        if self.args.offset:
            print("%s" % self.probe.bpf.symaddr(addr, pid_for_syms))
        else:
            print("%s" % self.probe.bpf.sym(addr, pid_for_syms))

    @staticmethod
    def _signal_ignore(signal, frame):
        print()

    def run(self):
        self.probe.load()
        self.probe.attach()
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

            counts = self.probe.bpf["counts"]
            stack_traces = self.probe.bpf["stack_traces"]
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
        Tool().run()
    except Exception:
        if debug:
            traceback.print_exc()
        elif sys.exc_info()[0] is not SystemExit:
            print(sys.exc_info()[1])


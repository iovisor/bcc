#!/usr/bin/env python
#
# stackcount    Count events and their stack traces.
#               For Linux, uses BCC, eBPF.
#
# USAGE: stackcount [-h] [-p PID] [-i INTERVAL] [-T] [-r] [-s]
#                   [-P] [-v] pattern
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
from bcc import BPF, USDT
from time import sleep, strftime
import argparse
import re
import signal
import sys
import traceback

debug = False

class Probe(object):
    def __init__(self, pattern, use_regex=False, pid=None, per_pid=False):
        """Init a new probe.

        Init the probe from the pattern provided by the user. The supported
        patterns mimic the 'trace' and 'argdist' tools, but are simpler because
        we don't have to distinguish between probes and retprobes.

            func            -- probe a kernel function
            lib:func        -- probe a user-space function in the library 'lib'
            p::func         -- same thing as 'func'
            p:lib:func      -- same thing as 'lib:func'
            t:cat:event     -- probe a kernel tracepoint
            u:lib:probe     -- probe a USDT tracepoint
        """
        parts = pattern.split(':')
        if len(parts) == 1:
            parts = ["p", "", parts[0]]
        elif len(parts) == 2:
            parts = ["p", parts[0], parts[1]]
        elif len(parts) == 3:
            if parts[0] == "t":
                parts = ["t", "", "%s:%s" % tuple(parts[1:])]
            if parts[0] not in ["p", "t", "u"]:
                raise Exception("Type must be 'p', 't', or 'u', but got %s" %
                                parts[0])
        else:
            raise Exception("Too many ':'-separated components in pattern %s" %
                            pattern)

        (self.type, self.library, self.pattern) = parts
        if not use_regex:
            self.pattern = self.pattern.replace('*', '.*')
            self.pattern = '^' + self.pattern + '$'

        if (self.type == "p" and self.library) or self.type == "u":
            libpath = BPF.find_library(self.library)
            if libpath is None:
                # This might be an executable (e.g. 'bash')
                libpath = BPF.find_exe(self.library)
            if libpath is None or len(libpath) == 0:
                raise Exception("unable to find library %s" % self.library)
            self.library = libpath

        self.pid = pid
        self.per_pid = per_pid
        self.matched = 0

    def is_kernel_probe(self):
        return self.type == "t" or (self.type == "p" and self.library == "")

    def attach(self):
        if self.type == "p":
            if self.library:
                self.bpf.attach_uprobe(name=self.library,
                                       sym_re=self.pattern,
                                       fn_name="trace_count",
                                       pid=self.pid or -1)
                self.matched = self.bpf.num_open_uprobes()
            else:
                self.bpf.attach_kprobe(event_re=self.pattern,
                                       fn_name="trace_count",
                                       pid=self.pid or -1)
                self.matched = self.bpf.num_open_kprobes()
        elif self.type == "t":
            self.bpf.attach_tracepoint(tp_re=self.pattern,
                                       fn_name="trace_count",
                                       pid=self.pid or -1)
            self.matched = self.bpf.num_open_tracepoints()
        elif self.type == "u":
            pass    # Nothing to do -- attach already happened in `load`

        if self.matched == 0:
            raise Exception("No functions matched by pattern %s" %
                            self.pattern)

    def load(self):
        trace_count_text = """
int trace_count(void *ctx) {
    FILTER
    struct key_t key = {};
    key.pid = GET_PID;
    key.stackid = stack_traces.get_stackid(ctx, STACK_FLAGS);
    u64 zero = 0;
    u64 *val = counts.lookup_or_init(&key, &zero);
    (*val)++;
    return 0;
}
        """
        bpf_text = """#include <uapi/linux/ptrace.h>

struct key_t {
    u32 pid;
    int stackid;
};

BPF_HASH(counts, struct key_t);
BPF_STACK_TRACE(stack_traces, 1024);

        """

        # We really mean the tgid from the kernel's perspective, which is in
        # the top 32 bits of bpf_get_current_pid_tgid().
        if self.is_kernel_probe() and self.pid:
            trace_count_text = trace_count_text.replace('FILTER',
                ('u32 pid; pid = bpf_get_current_pid_tgid() >> 32; ' +
                'if (pid != %d) { return 0; }') % (self.pid))
        else:
            trace_count_text = trace_count_text.replace('FILTER', '')

        # We need per-pid statistics when tracing a user-space process, because
        # the meaning of the symbols depends on the pid. We also need them if
        # per-pid statistics were requested with -P.
        if self.per_pid or not self.is_kernel_probe():
            trace_count_text = trace_count_text.replace('GET_PID',
                                        'bpf_get_current_pid_tgid() >> 32')
        else:
            trace_count_text = trace_count_text.replace(
                                    'GET_PID', '0xffffffff')

        stack_flags = 'BPF_F_REUSE_STACKID'
        if not self.is_kernel_probe():
            stack_flags += '| BPF_F_USER_STACK'     # can't do both U *and* K
        trace_count_text = trace_count_text.replace('STACK_FLAGS', stack_flags)

        self.usdt = None
        if self.type == "u":
            self.usdt = USDT(path=self.library, pid=self.pid)
            for probe in self.usdt.enumerate_probes():
                if not self.pid and (probe.bin_path != self.library):
                    continue
                if re.match(self.pattern, probe.name):
                    # This hack is required because the bpf_usdt_readarg
                    # functions generated need different function names for
                    # each attached probe. If we just stick to trace_count,
                    # we'd get multiple bpf_usdt_readarg helpers with the same
                    # name when enabling more than one USDT probe.
                    new_func = "trace_count_%d" % self.matched
                    bpf_text += trace_count_text.replace(
                                            "trace_count", new_func)
                    self.usdt.enable_probe(probe.name, new_func)
                    self.matched += 1
            if debug:
                print(self.usdt.get_text())
        else:
            bpf_text += trace_count_text

        if debug:
            print(bpf_text)
        self.bpf = BPF(text=bpf_text,
                       usdt_contexts=[self.usdt] if self.usdt else [])

class Tool(object):
    def __init__(self):
        examples = """examples:
    ./stackcount submit_bio         # count kernel stack traces for submit_bio
    ./stackcount -s ip_output       # show symbol offsets
    ./stackcount -sv ip_output      # show offsets and raw addresses (verbose)
    ./stackcount 'tcp_send*'        # count stacks for funcs matching tcp_send*
    ./stackcount -r '^tcp_send.*'   # same as above, using regular expressions
    ./stackcount -Ti 5 ip_output    # output every 5 seconds, with timestamps
    ./stackcount -p 185 ip_output   # count ip_output stacks for PID 185 only
    ./stackcount -p 185 c:malloc    # count stacks for malloc in PID 185
    ./stackcount t:sched:sched_fork # count stacks for sched_fork tracepoint
    ./stackcount -p 185 u:node:*    # count stacks for all USDT probes in node
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
        parser.add_argument("-P", "--perpid", action="store_true",
            help="display stacks separately for each process")
        parser.add_argument("-v", "--verbose", action="store_true",
            help="show raw addresses")
        parser.add_argument("-d", "--debug", action="store_true",
            help="print BPF program before starting (for debugging purposes)")
        parser.add_argument("pattern",
            help="search expression for events")
        self.args = parser.parse_args()
        global debug
        debug = self.args.debug
        self.probe = Probe(self.args.pattern, self.args.regexp,
                           self.args.pid, self.args.perpid)

    def _print_frame(self, addr, pid):
        print("  ", end="")
        if self.args.verbose:
            print("%-16x " % addr, end="")
        if self.args.offset:
            print("%s" % self.probe.bpf.sym(addr, pid, show_offset=True))
        else:
            print("%s" % self.probe.bpf.sym(addr, pid))

    @staticmethod
    def _signal_ignore(signal, frame):
        print()

    def _comm_for_pid(self, pid):
        if pid in self.comm_cache:
            return self.comm_cache[pid]

        try:
            comm = "    %s [%d]" % (
                    open("/proc/%d/comm" % pid).read().strip(),
                    pid)
            self.comm_cache[pid] = comm
            return comm
        except:
            return "    unknown process [%d]" % pid

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
            self.comm_cache = {}
            for k, v in sorted(counts.items(),
                               key=lambda counts: counts[1].value):
                for addr in stack_traces.walk(k.stackid):
                    pid = -1 if self.probe.is_kernel_probe() else k.pid
                    self._print_frame(addr, pid)
                if not self.args.pid and k.pid != 0xffffffff:
                    print(self._comm_for_pid(k.pid))
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

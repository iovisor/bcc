#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# ustat  Activity stats from high-level languages, including exceptions,
#        method calls, class loads, garbage collections, and more.
#        For Linux, uses BCC, eBPF.
#
# USAGE: ustat [-l {java,node,perl,php,python,ruby,tcl}] [-C]
#        [-S {cload,excp,gc,method,objnew,thread}] [-r MAXROWS] [-d]
#        [interval [count]]
#
# This uses in-kernel eBPF maps to store per process summaries for efficiency.
# Newly-created processes might only be traced at the next interval, if the
# relevant USDT probe requires enabling through a semaphore.
#
# Copyright 2016 Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 26-Oct-2016   Sasha Goldshtein    Created this.

from __future__ import print_function
import argparse
from bcc import BPF, USDT
import os
from subprocess import call
from time import sleep, strftime

class Category(object):
    THREAD = "THREAD"
    METHOD = "METHOD"
    OBJNEW = "OBJNEW"
    CLOAD = "CLOAD"
    EXCP = "EXCP"
    GC = "GC"

class Probe(object):
    def __init__(self, language, procnames, events):
        """
        Initialize a new probe object with a specific language, set of process
        names to monitor for that language, and a dictionary of events and
        categories. The dictionary is a mapping of USDT probe names (such as
        'gc__start') to event categories supported by this tool -- from the
        Category class.
        """
        self.language = language
        self.procnames = procnames
        self.events = events

    def _find_targets(self):
        """Find pids where the comm is one of the specified list"""
        self.targets = {}
        all_pids = [int(pid) for pid in os.listdir('/proc') if pid.isdigit()]
        for pid in all_pids:
            try:
                comm = open('/proc/%d/comm' % pid).read().strip()
                if comm in self.procnames:
                    cmdline = open('/proc/%d/cmdline' % pid).read()
                    self.targets[pid] = cmdline.replace('\0', ' ')
            except IOError:
                continue    # process may already have terminated

    def _enable_probes(self):
        self.usdts = []
        for pid in self.targets:
            usdt = USDT(pid=pid)
            for event in self.events:
                try:
                    usdt.enable_probe(event, "%s_%s" % (self.language, event))
                except Exception:
                    # This process might not have a recent version of the USDT
                    # probes enabled, or might have been compiled without USDT
                    # probes at all. The process could even have been shut down
                    # and the pid been recycled. We have to gracefully handle
                    # the possibility that we can't attach probes to it at all.
                    pass
            self.usdts.append(usdt)

    def _generate_tables(self):
        text = """
BPF_HASH(%s_%s_counts, u32, u64);   // pid to event count
        """
        return str.join('', [text % (self.language, event)
                             for event in self.events])

    def _generate_functions(self):
        text = """
int %s_%s(void *ctx) {
    u64 *valp, zero = 0;
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    valp = %s_%s_counts.lookup_or_init(&tgid, &zero);
    ++(*valp);
    return 0;
}
        """
        lang = self.language
        return str.join('', [text % (lang, event, lang, event)
                             for event in self.events])

    def get_program(self):
        self._find_targets()
        self._enable_probes()
        return self._generate_tables() + self._generate_functions()

    def get_usdts(self):
        return self.usdts

    def get_counts(self, bpf):
        """Return a map of event counts per process"""
        event_dict = dict([(category, 0) for category in self.events.values()])
        result = dict([(pid, event_dict.copy()) for pid in self.targets])
        for event, category in self.events.items():
            counts = bpf["%s_%s_counts" % (self.language, event)]
            for pid, count in counts.items():
                result[pid.value][category] = count.value
            counts.clear()
        return result

    def cleanup(self):
        self.usdts = None

class Tool(object):
    def _parse_args(self):
        examples = """examples:
  ./ustat              # stats for all languages, 1 second refresh
  ./ustat -C           # don't clear the screen
  ./ustat -l java      # Java processes only
  ./ustat 5            # 5 second summaries
  ./ustat 5 10         # 5 second summaries, 10 times only
        """
        parser = argparse.ArgumentParser(
            description="Activity stats from high-level languages.",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=examples)
        parser.add_argument("-l", "--language",
            choices=["java", "node", "perl", "php", "python", "ruby", "tcl"],
            help="language to trace (default: all languages)")
        parser.add_argument("-C", "--noclear", action="store_true",
            help="don't clear the screen")
        parser.add_argument("-S", "--sort",
            choices=[cat.lower() for cat in dir(Category) if cat.isupper()],
            help="sort by this field (descending order)")
        parser.add_argument("-r", "--maxrows", default=20, type=int,
            help="maximum rows to print, default 20")
        parser.add_argument("-d", "--debug", action="store_true",
            help="Print the resulting BPF program (for debugging purposes)")
        parser.add_argument("interval", nargs="?", default=1, type=int,
            help="output interval, in seconds")
        parser.add_argument("count", nargs="?", default=99999999, type=int,
            help="number of outputs")
        parser.add_argument("--ebpf", action="store_true",
            help=argparse.SUPPRESS)
        self.args = parser.parse_args()

    def _create_probes(self):
        probes_by_lang = {
                "java": Probe("java", ["java"], {
                    "gc__begin": Category.GC,
                    "mem__pool__gc__begin": Category.GC,
                    "thread__start": Category.THREAD,
                    "class__loaded": Category.CLOAD,
                    "object__alloc": Category.OBJNEW,
                    "method__entry": Category.METHOD,
                    "ExceptionOccurred__entry": Category.EXCP
                    }),
                "node": Probe("node", ["node"], {
                    "gc__start": Category.GC
                    }),
                "perl": Probe("perl", ["perl"], {
                    "sub__entry": Category.METHOD
                    }),
                "php": Probe("php", ["php"], {
                    "function__entry": Category.METHOD,
                    "compile__file__entry": Category.CLOAD,
                    "exception__thrown": Category.EXCP
                    }),
                "python": Probe("python", ["python"], {
                    "function__entry": Category.METHOD,
                    "gc__start": Category.GC
                    }),
                "ruby": Probe("ruby", ["ruby", "irb"], {
                    "method__entry": Category.METHOD,
                    "cmethod__entry": Category.METHOD,
                    "gc__mark__begin": Category.GC,
                    "gc__sweep__begin": Category.GC,
                    "object__create": Category.OBJNEW,
                    "hash__create": Category.OBJNEW,
                    "string__create": Category.OBJNEW,
                    "array__create": Category.OBJNEW,
                    "require__entry": Category.CLOAD,
                    "load__entry": Category.CLOAD,
                    "raise": Category.EXCP
                    }),
                "tcl": Probe("tcl", ["tclsh", "wish"], {
                    "proc__entry": Category.METHOD,
                    "obj__create": Category.OBJNEW
                    }),
                }

        if self.args.language:
            self.probes = [probes_by_lang[self.args.language]]
        else:
            self.probes = probes_by_lang.values()

    def _attach_probes(self):
        program = str.join('\n', [p.get_program() for p in self.probes])
        if self.args.debug or self.args.ebpf:
            print(program)
            if self.args.ebpf:
                exit()
            for probe in self.probes:
                print("Attached to %s processes:" % probe.language,
                        str.join(', ', map(str, probe.targets)))
        self.bpf = BPF(text=program)
        usdts = [usdt for probe in self.probes for usdt in probe.get_usdts()]
        # Filter out duplicates when we have multiple processes with the same
        # uprobe. We are attaching to these probes manually instead of using
        # the USDT support from the bcc module, because the USDT class attaches
        # to each uprobe with a specific pid. When there is more than one
        # process from some language, we end up attaching more than once to the
        # same uprobe (albeit with different pids), which is not allowed.
        # Instead, we use a global attach (with pid=-1).
        uprobes = set([(path, func, addr) for usdt in usdts
                       for (path, func, addr, _)
                       in usdt.enumerate_active_probes()])
        for (path, func, addr) in uprobes:
            self.bpf.attach_uprobe(name=path, fn_name=func, addr=addr, pid=-1)

    def _detach_probes(self):
        for probe in self.probes:
            probe.cleanup()     # Cleans up USDT contexts
        self.bpf.cleanup()      # Cleans up all attached probes
        self.bpf = None

    def _loop_iter(self):
        self._attach_probes()
        try:
            sleep(self.args.interval)
        except KeyboardInterrupt:
            self.exiting = True

        if not self.args.noclear:
            call("clear")
        else:
            print()
        with open("/proc/loadavg") as stats:
            print("%-8s loadavg: %s" % (strftime("%H:%M:%S"), stats.read()))
        print("%-6s %-20s %-10s %-6s %-10s %-8s %-6s %-6s" % (
            "PID", "CMDLINE", "METHOD/s", "GC/s", "OBJNEW/s",
            "CLOAD/s", "EXC/s", "THR/s"))

        line = 0
        counts = {}
        targets = {}
        for probe in self.probes:
            counts.update(probe.get_counts(self.bpf))
            targets.update(probe.targets)
        if self.args.sort:
            sort_field = self.args.sort.upper()
            counts = sorted(counts.items(),
                            key=lambda kv: -kv[1].get(sort_field, 0))
        else:
            counts = sorted(counts.items(), key=lambda kv: kv[0])
        for pid, stats in counts:
            print("%-6d %-20s %-10d %-6d %-10d %-8d %-6d %-6d" % (
                  pid, targets[pid][:20],
                  stats.get(Category.METHOD, 0) / self.args.interval,
                  stats.get(Category.GC, 0) / self.args.interval,
                  stats.get(Category.OBJNEW, 0) / self.args.interval,
                  stats.get(Category.CLOAD, 0) / self.args.interval,
                  stats.get(Category.EXCP, 0) / self.args.interval,
                  stats.get(Category.THREAD, 0) / self.args.interval
                  ))
            line += 1
            if line >= self.args.maxrows:
                break
        self._detach_probes()

    def run(self):
        self._parse_args()
        self._create_probes()
        print('Tracing... Output every %d secs. Hit Ctrl-C to end' %
              self.args.interval)
        countdown = self.args.count
        self.exiting = False
        while True:
            self._loop_iter()
            countdown -= 1
            if self.exiting or countdown == 0:
                print("Detaching...")
                exit()

if __name__ == "__main__":
    try:
        Tool().run()
    except KeyboardInterrupt:
        pass

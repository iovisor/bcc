#!/usr/bin/env python
#
# tplist    Display kernel tracepoints or USDT probes and their formats.
#
# USAGE:    tplist [-p PID] [-l LIB] [-v] [filter]
#
# Licensed under the Apache License, Version 2.0 (the "License")
# Copyright (C) 2016 Sasha Goldshtein.

import argparse
import fnmatch
import os
import re
import sys

from bcc import USDT

trace_root = "/sys/kernel/debug/tracing"
event_root = os.path.join(trace_root, "events")

parser = argparse.ArgumentParser(
        description="Display kernel tracepoints or USDT probes " +
                    "and their formats.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-p", "--pid", type=int, default=None,
        help="List USDT probes in the specified process")
parser.add_argument("-l", "--lib", default="",
        help="List USDT probes in the specified library or executable")
parser.add_argument("-v", dest="verbosity", action="count", default=0,
        help="Increase verbosity level (print variables, arguments, etc.)")
parser.add_argument(dest="filter", nargs="?",
        help="A filter that specifies which probes/tracepoints to print")
args = parser.parse_args()

def print_tpoint_format(category, event):
        fmt = open(os.path.join(event_root, category, event, "format")) \
              .readlines()
        for line in fmt:
                match = re.search(r'field:([^;]*);', line)
                if match is None:
                        continue
                parts = match.group(1).split()
                field_name = parts[-1:][0]
                field_type = " ".join(parts[:-1])
                if field_name.startswith("common_"):
                        continue
                print("    %s %s;" % (field_type, field_name))

def print_tpoint(category, event):
        tpoint = "%s:%s" % (category, event)
        if not args.filter or fnmatch.fnmatch(tpoint, args.filter):
                print(tpoint)
                if args.verbosity > 0:
                        print_tpoint_format(category, event)

def print_tracepoints():
        for category in os.listdir(event_root):
                cat_dir = os.path.join(event_root, category)
                if not os.path.isdir(cat_dir):
                        continue
                for event in os.listdir(cat_dir):
                        evt_dir = os.path.join(cat_dir, event)
                        if os.path.isdir(evt_dir):
                                print_tpoint(category, event)

def print_usdt_argument_details(location):
        for idx in range(0, location.num_arguments):
                arg = location.get_argument(idx)
                print("    argument #%d %s" % (idx + 1, arg))

def print_usdt_details(probe):
        if args.verbosity > 0:
                print(probe)
                if args.verbosity > 1:
                        for idx in range(0, probe.num_locations):
                                loc = probe.get_location(idx)
                                print("  location #%d %s" % (idx + 1, loc))
                                print_usdt_argument_details(loc)
                else:
                        print("  %d location(s)" % probe.num_locations)
                        print("  %d argument(s)" % probe.num_arguments)
        else:
                print("%s %s:%s" %
                      (probe.bin_path, probe.provider, probe.name))

def print_usdt(pid, lib):
        reader = USDT(path=lib, pid=pid)
        probes_seen = []
        for probe in reader.enumerate_probes():
                probe_name = probe.short_name()
                if not args.filter or fnmatch.fnmatch(probe_name, args.filter):
                        if probe_name in probes_seen:
                                continue
                        probes_seen.append(probe_name)
                        print_usdt_details(probe)

if __name__ == "__main__":
        try:
                if args.pid or args.lib != "":
                        print_usdt(args.pid, args.lib)
                else:
                        print_tracepoints()
        except:
                if sys.exc_info()[0] is not SystemExit:
                        print(sys.exc_info()[1])

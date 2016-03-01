#!/usr/bin/env python
#
# tplist    Display kernel tracepoints and their formats.
#
# USAGE:    tplist [-v] [tracepoint]
#
# Licensed under the Apache License, Version 2.0 (the "License")
# Copyright (C) 2016 Sasha Goldshtein.

import argparse
import fnmatch
import re
import os

trace_root = "/sys/kernel/debug/tracing"
event_root = os.path.join(trace_root, "events")

parser = argparse.ArgumentParser(description=
                "Display kernel tracepoints and their formats.",
                formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-v", dest="variables", action="store_true", help=
                "Print the format (available variables) for each tracepoint")
parser.add_argument(dest="tracepoint", nargs="?",
                help="The tracepoint name to print (wildcards allowed)")
args = parser.parse_args()

def print_tpoint_format(category, event):
        fmt = open(os.path.join(event_root, category, event, "format")
                  ).readlines()
        for line in fmt:
                match = re.search(r'field:([^;]*);', line)
                if match is None:
                        continue
                parts = match.group(1).split()
                field_name = parts[-1:][0]
                field_type = " ".join(parts[:-1])
                if "__data_loc" in field_type:
                        continue
                if field_name.startswith("common_"):
                        continue
                print("    %s %s;" % (field_type, field_name))

def print_tpoint(category, event):
        tpoint = "%s:%s" % (category, event)
        if not args.tracepoint or fnmatch.fnmatch(tpoint, args.tracepoint):
                print(tpoint)
                if args.variables:
                        print_tpoint_format(category, event)

def print_all():
        for category in os.listdir(event_root):
                cat_dir = os.path.join(event_root, category)
                if not os.path.isdir(cat_dir):
                        continue
                for event in os.listdir(cat_dir):
                        evt_dir = os.path.join(cat_dir, event)
                        if os.path.isdir(evt_dir):
                                print_tpoint(category, event)

if __name__ == "__main__":
        print_all()

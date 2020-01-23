#!/usr/bin/python
#
# bpflist   Display processes currently using BPF programs and maps,
#           pinned BPF programs and maps, and enabled probes.
#
# USAGE: bpflist [-v]
#
# Idea by Brendan Gregg.
#
# Copyright 2017, Sasha Goldshtein
# Licensed under the Apache License, Version 2.0
#
# 09-Mar-2017   Sasha Goldshtein   Created this.

from bcc import BPF, USDT
import argparse
import re
import os
import subprocess

examples = """examples:
    bpflist     # display all processes currently using BPF
    bpflist -v  # also count kprobes/uprobes
    bpflist -vv # display kprobes/uprobes and count them
"""
parser = argparse.ArgumentParser(
    description="Display processes currently using BPF programs and maps",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-v", "--verbosity", action="count", default=0,
    help="count and display kprobes/uprobes as well")
args = parser.parse_args()

def comm_for_pid(pid):
    try:
        return open("/proc/%d/comm" % pid).read().strip()
    except:
        return "[unknown]"

counts = {}

def parse_probes(typ):
    if args.verbosity > 1:
        print("open %ss:" % typ)
    for probe in open("/sys/kernel/debug/tracing/%s_events" % typ):
        # Probes opened by bcc have a specific pattern that includes the pid
        # of the requesting process.
        match = re.search('_bcc_(\\d+)\\s', probe)
        if match:
            pid = int(match.group(1))
            counts[(pid, typ)] = counts.get((pid, typ), 0) + 1
        if args.verbosity > 1:
            print(probe.strip())
    if args.verbosity > 1:
        print("")

if args.verbosity > 0:
    parse_probes("kprobe")
    parse_probes("uprobe")

def find_bpf_fds(pid):
    root = '/proc/%d/fd' % pid
    for fd in os.listdir(root):
        try:
            link = os.readlink(os.path.join(root, fd))
        except OSError:
            continue
        match = re.match('anon_inode:bpf-([\\w-]+)', link)
        if match:
            tup = (pid, match.group(1))
            counts[tup] = counts.get(tup, 0) + 1

for pdir in os.listdir('/proc'):
    if re.match('\\d+', pdir):
        try:
            find_bpf_fds(int(pdir))
        except OSError:
            continue

items = counts.items()
max_type_len = items and max(list(map(lambda t: len(t[0][1]), items))) or 0
print_format = "%%-6s %%-16s %%-%ss %%s" % (max_type_len + 1)

print(print_format % ("PID", "COMM", "TYPE", "COUNT"))
for (pid, typ), count in sorted(items, key=lambda t: t[0][0]):
    comm = comm_for_pid(pid)
    print(print_format % (pid, comm, typ, count))

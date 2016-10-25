#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# uobjnew  Summarize object allocations in high-level languages.
#          For Linux, uses BCC, eBPF.
#
# USAGE: uobjnew [-h] [-T TOP] [-v] {java,ruby,c} pid [interval]
#
# Copyright 2016 Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 25-Oct-2016   Sasha Goldshtein   Created this.

from __future__ import print_function
import argparse
from bcc import BPF, USDT
from time import sleep

examples = """examples:
    ./uobjnew -l java 145         # summarize Java allocations in process 145
    ./uobjnew -l c 2020 1         # grab malloc() sizes and print every second
    ./uobjnew -l ruby 6712 -C 10  # top 10 Ruby types by number of allocations
    ./uobjnew -l ruby 6712 -S 10  # top 10 Ruby types by total size
"""
parser = argparse.ArgumentParser(
    description="Summarize object allocations in high-level languages.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("language", choices=["java", "ruby", "c"],
    help="language to trace")
parser.add_argument("pid", type=int, help="process id to attach to")
parser.add_argument("interval", type=int, nargs='?',
    help="print every specified number of seconds")
parser.add_argument("-C", "--top-count", type=int,
    help="number of most frequently allocated types to print")
parser.add_argument("-S", "--top-size", type=int,
    help="number of largest types by allocated bytes to print")
parser.add_argument("-v", "--verbose", action="store_true",
    help="verbose mode: print the BPF program (for debugging purposes)")
args = parser.parse_args()

program = """
#include <linux/ptrace.h>

struct key_t {
#if MALLOC_TRACING
    u64 size;
#else
    char name[50];
#endif
};

struct val_t {
    u64 total_size;
    u64 num_allocs;
};

BPF_HASH(allocs, struct key_t, struct val_t);
""".replace("MALLOC_TRACING", "1" if args.language == "c" else "0")

usdt = USDT(pid=args.pid)

if args.language == "java":
    program += """
int alloc_entry(struct pt_regs *ctx) {
    struct key_t key = {};
    struct val_t *valp, zero = {};
    u64 classptr = 0, size = 0;
    bpf_usdt_readarg(2, ctx, &classptr);
    bpf_usdt_readarg(4, ctx, &size);
    bpf_probe_read(&key.name, sizeof(key.name), (void *)classptr);
    valp = allocs.lookup_or_init(&key, &zero);
    valp->total_size += size;
    valp->num_allocs += 1;
    return 0;
}
    """
    usdt.enable_probe("object__alloc", "alloc_entry")
elif args.language == "ruby":
    create_template = """
int THETHING_alloc_entry(struct pt_regs *ctx) {
    struct key_t key = { .name = "THETHING" };
    struct val_t *valp, zero = {};
    u64 size = 0;
    bpf_usdt_readarg(1, ctx, &size);
    valp = allocs.lookup_or_init(&key, &zero);
    valp->total_size += size;
    valp->num_allocs += 1;
    return 0;
}
    """
    program += """
int object_alloc_entry(struct pt_regs *ctx) {
    struct key_t key = {};
    struct val_t *valp, zero = {};
    u64 classptr = 0;
    bpf_usdt_readarg(1, ctx, &classptr);
    bpf_probe_read(&key.name, sizeof(key.name), (void *)classptr);
    valp = allocs.lookup_or_init(&key, &zero);
    valp->num_allocs += 1;  // We don't know the size, unfortunately
    return 0;
}
    """
    usdt.enable_probe("object__create", "object_alloc_entry")
    for thing in ["string", "hash", "array"]:
        program += create_template.replace("THETHING", thing)
        usdt.enable_probe("%s__create" % thing, "%s_alloc_entry" % thing)
elif args.language == "c":
    program += """
int alloc_entry(struct pt_regs *ctx, size_t size) {
    struct key_t key = {};
    struct val_t *valp, zero = {};
    key.size = size;
    valp = allocs.lookup_or_init(&key, &zero);
    valp->total_size += size;
    valp->num_allocs += 1;
    return 0;
}
    """

if args.verbose:
    print(usdt.get_text())
    print(program)

bpf = BPF(text=program, usdt_contexts=[usdt])
if args.language == "c":
    bpf.attach_uprobe(name="c", sym="malloc", fn_name="alloc_entry")

exit_signaled = False
print("Tracing allocations in process %d (language: %s)... Ctrl-C to quit." %
      (args.pid, args.language or "none"))
while True:
    try:
        sleep(args.interval or 99999999)
    except KeyboardInterrupt:
        exit_signaled = True
    print()
    data = bpf["allocs"]
    if args.top_count:
        data = sorted(data.items(), key=lambda (k, v): v.num_allocs)
        data = data[-args.top_count:]
    elif args.top_size:
        data = sorted(data.items(), key=lambda (k, v): v.total_size)
        data = data[-args.top_size:]
    else:
        data = sorted(data.items(), key=lambda (k, v): v.total_size)
    print("%-30s %8s %12s" % ("TYPE", "# ALLOCS", "# BYTES"))
    for key, value in data:
        if args.language == "c":
            obj_type = "block size %d" % key.size
        else:
            obj_type = key.name
        print("%-30s %8d %12d" %
              (obj_type, value.num_allocs, value.total_size))
    if args.interval and not exit_signaled:
        bpf["allocs"].clear()
    else:
        exit()

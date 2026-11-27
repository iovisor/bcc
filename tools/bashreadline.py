#!/usr/bin/env python3
#
# bashreadline Print entered bash commands from all running shells.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: bashreadline [-h] [-s [SHARED]] [-j] [-f [FILENAME]]
# This works by tracing the readline() function using a uretprobe (uprobes).
# When you failed to run the script directly with error:
# `Exception: could not determine address of symbol b'readline'`,
# you may need specify the location of libreadline.so library
# with `-s` option.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 28-Jan-2016    Brendan Gregg   Created this.
# 12-Feb-2016    Allan McAleavy migrated to BPF_PERF_OUTPUT
# 25-Feb-2025    Skip McGee added args, output and uid

from __future__ import print_function
from elftools.elf.elffile import ELFFile
from bcc import BPF
from time import strftime
import os
import argparse
import json

parser = argparse.ArgumentParser(
    description="Print entered bash commands from all running shells",
    formatter_class=argparse.RawDescriptionHelpFormatter,
)
parser.add_argument(
    "-f",
    "--file",
    nargs="?",
    type=argparse.FileType("a"),
    help="specify an output file for results.",
)
parser.add_argument(
    "-j",
    "--json",
    action="store_true",
    help="return each result as a JSON string.",
)
parser.add_argument(
    "-s",
    "--shared",
    nargs="?",
    const="/lib/libreadline.so",
    type=str,
    help="specify the location of libreadline.so library.\
              Default is /lib/libreadline.so",
)

args = parser.parse_args()

name = args.shared if args.shared else "/bin/bash"


def get_sym(filename):
    with open(filename, "rb") as f:
        elf = ELFFile(f)
        symbol_table = elf.get_section_by_name(".dynsym")
        for symbol in symbol_table.iter_symbols():
            if symbol.name == "readline_internal_teardown":
                return "readline_internal_teardown"
    return "readline"


sym = get_sym(name)

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct str_t {
    u32 uid;
    u32 pid;
    char str[400];
};
BPF_PERF_OUTPUT(events);

int printret(struct pt_regs *ctx) {
    struct str_t data  = {};
    char comm[TASK_COMM_LEN] = {};
    if (!PT_REGS_RC(ctx))
        return 0;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_probe_read_user(&data.str, sizeof(data.str), (void *)PT_REGS_RC(ctx));

    bpf_get_current_comm(&comm, sizeof(comm));
    if (comm[0] == 'b' && comm[1] == 'a' && comm[2] == 's' && comm[3] == 'h' && comm[4] == 0 ) {
        events.perf_submit(ctx,&data,sizeof(data));
    }


    return 0;
};
"""

b = BPF(text=bpf_text)
b.attach_uretprobe(name=name, sym=sym, fn_name="printret")

# header
if not args.json:
    banner = "%-20s %-7s %-6s %s" % ("TIME", "PID", "UID", "COMMAND")
    if args.file:
        if os.path.exists(args.file.name):
            file_size = os.stat(args.file.name).st_size
            if file_size == 0:
                with open(args.file.name, "w") as output_file:
                    output_file.write(banner + "\n")
        else:
            with open(args.file.name, "w") as output_file:
                output_file.write(banner + "\n")
    else:
        print(banner)


def print_event(cpu, data, size):
    event = b["events"].event(data)
    event_time = strftime("%Y/%m/%d-%H:%M:%S")
    if args.file:
        event_output = "%-20s %-7s %-6s %s" % (
            event_time,
            event.pid,
            event.uid,
            event.str.decode("utf-8", "replace").strip(),
        )
        with open(args.file.name, "a") as output_file:
            output_file.write(event_output + "\n")
    else:
        print(
            "%-20s %-7d %-6d %s"
            % (
                event_time,
                event.pid,
                event.uid,
                event.str.decode("utf-8", "replace").strip(),
            )
        )


def json_event(cpu, data, size):
    event = b["events"].event(data)
    json_data = dict()
    json_data["TIME"] = strftime("%Y/%m/%d-%H:%M:%S")
    json_data["PID"] = event.pid
    json_data["UID"] = event.uid
    json_data["COMMAND"] = event.str.decode("utf-8", "replace").strip()
    if args.file:
        with open(args.file.name, "a") as output_file:
            output_file.write(f"{json.dumps(json_data)}\n")
    else:
        print(str(json_data))


if args.json:
    b["events"].open_perf_buffer(json_event)
else:
    b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

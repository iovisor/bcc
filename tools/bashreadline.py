#!/usr/bin/python
#
# bashreadline  Print entered bash commands from all running shells.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: bashreadline [-s SHARED]
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

from __future__ import print_function
from bcc import BPF
from time import strftime
import argparse

parser = argparse.ArgumentParser(
        description="Print entered bash commands from all running shells",
        formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-s", "--shared", nargs="?",
        const="/lib/libreadline.so", type=str,
        help="specify the location of libreadline.so library.\
              Default is /lib/libreadline.so")
args = parser.parse_args()

name = args.shared if args.shared else "/bin/bash"

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct str_t {
    u64 pid;
    char str[80];
};

BPF_PERF_OUTPUT(events);

int printret(struct pt_regs *ctx) {
    struct str_t data  = {};
    char comm[TASK_COMM_LEN] = {};
    u32 pid;
    if (!PT_REGS_RC(ctx))
        return 0;
    pid = bpf_get_current_pid_tgid();
    data.pid = pid;
    bpf_probe_read_user(&data.str, sizeof(data.str), (void *)PT_REGS_RC(ctx));

    bpf_get_current_comm(&comm, sizeof(comm));
    if (comm[0] == 'b' && comm[1] == 'a' && comm[2] == 's' && comm[3] == 'h' && comm[4] == 0 ) {
        events.perf_submit(ctx,&data,sizeof(data));
    }


    return 0;
};
"""

b = BPF(text=bpf_text)
b.attach_uretprobe(name=name, sym="readline", fn_name="printret")

# header
print("%-9s %-6s %s" % ("TIME", "PID", "COMMAND"))

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%-9s %-6d %s" % (strftime("%H:%M:%S"), event.pid,
                            event.str.decode('utf-8', 'replace')))

b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

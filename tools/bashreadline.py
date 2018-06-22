#!/usr/bin/python
#
# bashreadline  Print entered bash commands from all running shells.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# This works by tracing the readline() function using a uretprobe (uprobes).
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 28-Jan-2016    Brendan Gregg   Created this.
# 12-Feb-2016    Allan McAleavy migrated to BPF_PERF_OUTPUT
# 22-Jun-2018    Michael Day converted to a Python class

from __future__ import print_function
from bcc import BPF
from time import strftime
import ctypes as ct
import json
import uuid

connect_string = "{Virtue-protocol-verion: 0.1}"
#"{Virtue-protocol-verion: 0.1, reply: [nonce, id, record 1] }\n"

STR_DATA = 80
class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulonglong),
        ("str", ct.c_char * STR_DATA)
    ]

class BashReadlineProbe:
    # load BPF program
    bpf_text = """
    #include <uapi/linux/ptrace.h>

    struct str_t {
        u64 pid;
        char str[80];
    };

    BPF_PERF_OUTPUT(events);

    int printret(struct pt_regs *ctx) {
        struct str_t data  = {};
        u32 pid;
        if (!PT_REGS_RC(ctx))
            return 0;
        pid = bpf_get_current_pid_tgid();
        data.pid = pid;
        bpf_probe_read(&data.str, sizeof(data.str), (void *)PT_REGS_RC(ctx));
        events.perf_submit(ctx,&data,sizeof(data));

        return 0;
    };
    """

    def __init__(self, json):
        self.b = BPF(text=self.bpf_text)
        self.b.attach_uretprobe(name="/bin/bash", sym="readline", fn_name="printret")
        self.json = json

        # header
        if not self.json:
            print("%-9s %-6s %s" % ("TIME", "PID", "COMMAND"))

        if self.json:
            self.b["events"].open_perf_buffer(self.print_event_json)
        else:
            self.b["events"].open_perf_buffer(self.print_event)

        while 1:
            self.b.perf_buffer_poll()


    def print_event(self, cpu, data, size):
        event = ct.cast(data, ct.POINTER(Data)).contents
        print("%-9s %-6d %s" % (strftime("%H:%M:%S"), event.pid,
                                event.str.decode()))

    def print_event_json(self, cpu, data, size):
        event = ct.cast(data, ct.POINTER(Data)).contents
        print('{"tag": bashreadline, "time": %s, "pid": %d, "command": %s}' \
              % (strftime("%H:%M:%S"), event.pid, event.str.decode()))

def client_main(args):

# arguments
    examples = """examples:
        ./bashreadline        # trace all readline syscalls by bash
        ./bashreadline -j     # output json objects
    """
    parser = argparse.ArgumentParser(
        description="Trace readline syscalls made by bash",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)

    parser.add_argument("-j", "--json", action="store_true",
                        help="output json objects")
    args = parser.parse_args()
    probe = BashReadlineProbe(args.json)


if __name__ == "__main__":
    import argparse, sys
    client_main(sys.argv)
    sys.exit(0)

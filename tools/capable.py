#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# capable   Trace security capabilitiy checks (cap_capable()).
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: capable [-h] [-v] [-p PID]
#
# ToDo: add -s for kernel stacks.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Sep-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime
import ctypes as ct

# arguments
examples = """examples:
    ./capable             # trace capability checks
    ./capable -v          # verbose: include non-audit checks
    ./capable -p 181      # only trace PID 181
"""
parser = argparse.ArgumentParser(
    description="Trace security capability checks",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-v", "--verbose", action="store_true",
    help="include non-audit checks")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
args = parser.parse_args()
debug = 0

# capabilities to names, generated from (and will need updating):
# awk '/^#define.CAP_.*[0-9]$/ { print "    " $3 ": \"" $2 "\"," }' \
#     include/uapi/linux/capability.h
capabilities = {
    0: "CAP_CHOWN",
    1: "CAP_DAC_OVERRIDE",
    2: "CAP_DAC_READ_SEARCH",
    3: "CAP_FOWNER",
    4: "CAP_FSETID",
    5: "CAP_KILL",
    6: "CAP_SETGID",
    7: "CAP_SETUID",
    8: "CAP_SETPCAP",
    9: "CAP_LINUX_IMMUTABLE",
    10: "CAP_NET_BIND_SERVICE",
    11: "CAP_NET_BROADCAST",
    12: "CAP_NET_ADMIN",
    13: "CAP_NET_RAW",
    14: "CAP_IPC_LOCK",
    15: "CAP_IPC_OWNER",
    16: "CAP_SYS_MODULE",
    17: "CAP_SYS_RAWIO",
    18: "CAP_SYS_CHROOT",
    19: "CAP_SYS_PTRACE",
    20: "CAP_SYS_PACCT",
    21: "CAP_SYS_ADMIN",
    22: "CAP_SYS_BOOT",
    23: "CAP_SYS_NICE",
    24: "CAP_SYS_RESOURCE",
    25: "CAP_SYS_TIME",
    26: "CAP_SYS_TTY_CONFIG",
    27: "CAP_MKNOD",
    28: "CAP_LEASE",
    29: "CAP_AUDIT_WRITE",
    30: "CAP_AUDIT_CONTROL",
    31: "CAP_SETFCAP",
    32: "CAP_MAC_OVERRIDE",
    33: "CAP_MAC_ADMIN",
    34: "CAP_SYSLOG",
    35: "CAP_WAKE_ALARM",
    36: "CAP_BLOCK_SUSPEND",
    37: "CAP_AUDIT_READ",
}

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
   // switch to u32s when supported
   u64 pid;
   u64 uid;
   int cap;
   int audit;
   char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

int kprobe__cap_capable(struct pt_regs *ctx, const struct cred *cred,
    struct user_namespace *targ_ns, int cap, int audit)
{
    u32 pid = bpf_get_current_pid_tgid();
    FILTER1
    FILTER2

    u32 uid = bpf_get_current_uid_gid();
    struct data_t data = {.pid = pid, .uid = uid, .cap = cap, .audit = audit};
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
};
"""
if args.pid:
    bpf_text = bpf_text.replace('FILTER1',
        'if (pid != %s) { return 0; }' % args.pid)
if not args.verbose:
    bpf_text = bpf_text.replace('FILTER2', 'if (audit == 0) { return 0; }')
bpf_text = bpf_text.replace('FILTER1', '')
bpf_text = bpf_text.replace('FILTER2', '')
if debug:
    print(bpf_text)

# initialize BPF
b = BPF(text=bpf_text)

TASK_COMM_LEN = 16    # linux/sched.h

class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulonglong),
        ("uid", ct.c_ulonglong),
        ("cap", ct.c_int),
        ("audit", ct.c_int),
        ("comm", ct.c_char * TASK_COMM_LEN)
    ]

# header
print("%-9s %-6s %-6s %-16s %-4s %-20s %s" % (
    "TIME", "UID", "PID", "COMM", "CAP", "NAME", "AUDIT"))

# process event
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents

    if event.cap in capabilities:
        name = capabilities[event.cap]
    else:
        name = "?"
    print("%-9s %-6d %-6d %-16s %-4d %-20s %d" % (strftime("%H:%M:%S"),
        event.uid, event.pid, event.comm.decode('utf-8', 'replace'),
        event.cap, name, event.audit))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()

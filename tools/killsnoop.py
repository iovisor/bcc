#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# killsnoop Trace signals issued by the kill() syscall.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: killsnoop [-h] [-x] [-p PID]
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 20-Sep-2015   Brendan Gregg   Created this.
# 19-Feb-2016   Allan McAleavy migrated to BPF_PERF_OUTPUT

from __future__ import print_function
from bcc import BPF
from bcc.utils import ArgString, printb
import argparse
from time import strftime
import ctypes as ct

# arguments
examples = """examples:
    ./killsnoop           # trace all kill() signals
    ./killsnoop -x        # only show failed kills
    ./killsnoop -p 181    # only trace PID 181
"""
parser = argparse.ArgumentParser(
    description="Trace signals issued by the kill() syscall",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-x", "--failed", action="store_true",
    help="only show failed kill syscalls")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct val_t {
   u64 pid;
   int sig;
   int tpid;
   char comm[TASK_COMM_LEN];
};

struct data_t {
   u64 pid;
   int tpid;
   int sig;
   int ret;
   char comm[TASK_COMM_LEN];
};

BPF_HASH(infotmp, u32, struct val_t);
BPF_PERF_OUTPUT(events);

int syscall__kill(struct pt_regs *ctx, int tpid, int sig)
{
    u32 pid = bpf_get_current_pid_tgid();
    FILTER

    struct val_t val = {.pid = pid};
    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        val.tpid = tpid;
        val.sig = sig;
        infotmp.update(&pid, &val);
    }

    return 0;
};

int do_ret_sys_kill(struct pt_regs *ctx)
{
    struct data_t data = {};
    struct val_t *valp;
    u32 pid = bpf_get_current_pid_tgid();

    valp = infotmp.lookup(&pid);
    if (valp == 0) {
        // missed entry
        return 0;
    }

    bpf_probe_read(&data.comm, sizeof(data.comm), valp->comm);
    data.pid = pid;
    data.tpid = valp->tpid;
    data.ret = PT_REGS_RC(ctx);
    data.sig = valp->sig;

    events.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&pid);

    return 0;
}
"""
if args.pid:
    bpf_text = bpf_text.replace('FILTER',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '')
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text)
kill_fnname = b.get_syscall_fnname("kill")
b.attach_kprobe(event=kill_fnname, fn_name="syscall__kill")
b.attach_kretprobe(event=kill_fnname, fn_name="do_ret_sys_kill")


TASK_COMM_LEN = 16    # linux/sched.h

class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulonglong),
        ("tpid", ct.c_int),
        ("sig", ct.c_int),
        ("ret", ct.c_int),
        ("comm", ct.c_char * TASK_COMM_LEN)
    ]

# header
print("%-9s %-6s %-16s %-4s %-6s %s" % (
    "TIME", "PID", "COMM", "SIG", "TPID", "RESULT"))

# process event
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents

    if (args.failed and (event.ret >= 0)):
        return

    printb(b"%-9s %-6d %-16s %-4d %-6d %d" % (strftime("%H:%M:%S").encode('ascii'),
        event.pid, event.comm, event.sig, event.tpid, event.ret))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()

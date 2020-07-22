#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# opensnoop Trace open() syscalls.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: opensnoop [-h] [-T] [-x] [-p PID] [-d DURATION] [-t TID] [-n NAME]
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 17-Sep-2015   Brendan Gregg   Created this.
# 29-Apr-2016   Allan McAleavy  Updated for BPF_PERF_OUTPUT.
# 08-Oct-2016   Dina Goldshtein Support filtering by PID and TID.
# 28-Dec-2018   Tim Douglas     Print flags argument, enable filtering
# 06-Jan-2019   Takuma Kume     Support filtering by UID

from __future__ import print_function
from bcc import ArgString, BPF
from bcc.containers import filter_by_containers
from bcc.utils import printb
import argparse
from datetime import datetime, timedelta
import os

# arguments
examples = """examples:
    ./opensnoop           # trace all open() syscalls
    ./opensnoop -T        # include timestamps
    ./opensnoop -U        # include UID
    ./opensnoop -x        # only show failed opens
    ./opensnoop -p 181    # only trace PID 181
    ./opensnoop -t 123    # only trace TID 123
    ./opensnoop -u 1000   # only trace UID 1000
    ./opensnoop -d 10     # trace for 10 seconds only
    ./opensnoop -n main   # only print process names containing "main"
    ./opensnoop -e        # show extended fields
    ./opensnoop -f O_WRONLY -f O_RDWR  # only print calls for writing
    ./opensnoop --cgroupmap mappath  # only trace cgroups in this BPF map
    ./opensnoop --mntnsmap mappath   # only trace mount namespaces in the map
"""
parser = argparse.ArgumentParser(
    description="Trace open() syscalls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-U", "--print-uid", action="store_true",
    help="print UID column")
parser.add_argument("-x", "--failed", action="store_true",
    help="only show failed opens")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-t", "--tid",
    help="trace this TID only")
parser.add_argument("--cgroupmap",
    help="trace cgroups in this BPF map only")
parser.add_argument("--mntnsmap",
    help="trace mount namespaces in this BPF map only")
parser.add_argument("-u", "--uid",
    help="trace this UID only")
parser.add_argument("-d", "--duration",
    help="total duration of trace in seconds")
parser.add_argument("-n", "--name",
    type=ArgString,
    help="only print process names containing this name")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
parser.add_argument("-e", "--extended_fields", action="store_true",
    help="show extended fields")
parser.add_argument("-f", "--flag_filter", action="append",
    help="filter on flags argument (e.g., O_WRONLY)")
args = parser.parse_args()
debug = 0
if args.duration:
    args.duration = timedelta(seconds=int(args.duration))
flag_filter_mask = 0
for flag in args.flag_filter or []:
    if not flag.startswith('O_'):
        exit("Bad flag: %s" % flag)
    try:
        flag_filter_mask |= getattr(os, flag)
    except AttributeError:
        exit("Bad flag: %s" % flag)

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>

struct val_t {
    u64 id;
    char comm[TASK_COMM_LEN];
    const char *fname;
    int flags; // EXTENDED_STRUCT_MEMBER
};

struct data_t {
    u64 id;
    u64 ts;
    u32 uid;
    int ret;
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
    int flags; // EXTENDED_STRUCT_MEMBER
};

BPF_PERF_OUTPUT(events);
"""

bpf_text_kprobe = """
BPF_HASH(infotmp, u64, struct val_t);

int trace_return(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp;
    struct data_t data = {};

    u64 tsp = bpf_ktime_get_ns();

    valp = infotmp.lookup(&id);
    if (valp == 0) {
        // missed entry
        return 0;
    }
    bpf_probe_read_kernel(&data.comm, sizeof(data.comm), valp->comm);
    bpf_probe_read_user(&data.fname, sizeof(data.fname), (void *)valp->fname);
    data.id = valp->id;
    data.ts = tsp / 1000;
    data.uid = bpf_get_current_uid_gid();
    data.flags = valp->flags; // EXTENDED_STRUCT_MEMBER
    data.ret = PT_REGS_RC(ctx);

    events.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&id);

    return 0;
}
"""

bpf_text_kprobe_header_open = """
int syscall__trace_entry_open(struct pt_regs *ctx, const char __user *filename, int flags)
{
"""

bpf_text_kprobe_header_openat = """
int syscall__trace_entry_openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags)
{
"""

bpf_text_kprobe_header_openat2 = """
#include <uapi/linux/openat2.h>
int syscall__trace_entry_openat2(struct pt_regs *ctx, int dfd, const char __user *filename, struct open_how *how)
{
    int flags = how->flags;
"""

bpf_text_kprobe_body = """
    struct val_t val = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part
    u32 uid = bpf_get_current_uid_gid();

    PID_TID_FILTER
    UID_FILTER
    FLAGS_FILTER

    if (container_should_be_filtered()) {
        return 0;
    }

    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        val.id = id;
        val.fname = filename;
        val.flags = flags; // EXTENDED_STRUCT_MEMBER
        infotmp.update(&id, &val);
    }

    return 0;
};
"""

bpf_text_kfunc_header_open = """
#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER) && !defined(__s390x__)
KRETFUNC_PROBE(FNNAME, struct pt_regs *regs, int ret)
{
    const char __user *filename = (char *)PT_REGS_PARM1(regs);
    int flags = PT_REGS_PARM2(regs);
#else
KRETFUNC_PROBE(FNNAME, const char __user *filename, int flags, int ret)
{
#endif
"""

bpf_text_kfunc_header_openat = """
#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER) && !defined(__s390x__)
KRETFUNC_PROBE(FNNAME, struct pt_regs *regs, int ret)
{
    int dfd = PT_REGS_PARM1(regs);
    const char __user *filename = (char *)PT_REGS_PARM2(regs);
    int flags = PT_REGS_PARM3(regs);
#else
KRETFUNC_PROBE(FNNAME, int dfd, const char __user *filename, int flags, int ret)
{
#endif
"""

bpf_text_kfunc_header_openat2 = """
#include <uapi/linux/openat2.h>
#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER) && !defined(__s390x__)
KRETFUNC_PROBE(FNNAME, struct pt_regs *regs, int ret)
{
    int dfd = PT_REGS_PARM1(regs);
    const char __user *filename = (char *)PT_REGS_PARM2(regs);
    struct open_how __user *how = (struct open_how *)PT_REGS_PARM3(regs);
    int flags = how->flags;
#else
KRETFUNC_PROBE(FNNAME, int dfd, const char __user *filename, struct open_how __user *how, int ret)
{
    int flags = how->flags;
#endif
"""

bpf_text_kfunc_body = """
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part
    u32 uid = bpf_get_current_uid_gid();

    PID_TID_FILTER
    UID_FILTER
    FLAGS_FILTER
    if (container_should_be_filtered()) {
        return 0;
    }

    struct data_t data = {};
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    u64 tsp = bpf_ktime_get_ns();

    bpf_probe_read_user(&data.fname, sizeof(data.fname), (void *)filename);
    data.id    = id;
    data.ts    = tsp / 1000;
    data.uid   = bpf_get_current_uid_gid();
    data.flags = flags; // EXTENDED_STRUCT_MEMBER
    data.ret   = ret;

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

b = BPF(text='')
# open and openat are always in place since 2.6.16
fnname_open = b.get_syscall_prefix().decode() + 'open'
fnname_openat = b.get_syscall_prefix().decode() + 'openat'
fnname_openat2 = b.get_syscall_prefix().decode() + 'openat2'
if b.ksymname(fnname_openat2) == -1:
    fnname_openat2 = None

is_support_kfunc = BPF.support_kfunc()
if is_support_kfunc:
    bpf_text += bpf_text_kfunc_header_open.replace('FNNAME', fnname_open)
    bpf_text += bpf_text_kfunc_body

    bpf_text += bpf_text_kfunc_header_openat.replace('FNNAME', fnname_openat)
    bpf_text += bpf_text_kfunc_body

    if fnname_openat2:
        bpf_text += bpf_text_kfunc_header_openat2.replace('FNNAME', fnname_openat2)
        bpf_text += bpf_text_kfunc_body
else:
    bpf_text += bpf_text_kprobe

    bpf_text += bpf_text_kprobe_header_open
    bpf_text += bpf_text_kprobe_body

    bpf_text += bpf_text_kprobe_header_openat
    bpf_text += bpf_text_kprobe_body

    if fnname_openat2:
        bpf_text += bpf_text_kprobe_header_openat2
        bpf_text += bpf_text_kprobe_body

if args.tid:  # TID trumps PID
    bpf_text = bpf_text.replace('PID_TID_FILTER',
        'if (tid != %s) { return 0; }' % args.tid)
elif args.pid:
    bpf_text = bpf_text.replace('PID_TID_FILTER',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('PID_TID_FILTER', '')
if args.uid:
    bpf_text = bpf_text.replace('UID_FILTER',
        'if (uid != %s) { return 0; }' % args.uid)
else:
    bpf_text = bpf_text.replace('UID_FILTER', '')
bpf_text = filter_by_containers(args) + bpf_text
if args.flag_filter:
    bpf_text = bpf_text.replace('FLAGS_FILTER',
        'if (!(flags & %d)) { return 0; }' % flag_filter_mask)
else:
    bpf_text = bpf_text.replace('FLAGS_FILTER', '')
if not (args.extended_fields or args.flag_filter):
    bpf_text = '\n'.join(x for x in bpf_text.split('\n')
        if 'EXTENDED_STRUCT_MEMBER' not in x)
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text)
if not is_support_kfunc:
    b.attach_kprobe(event=fnname_open, fn_name="syscall__trace_entry_open")
    b.attach_kretprobe(event=fnname_open, fn_name="trace_return")

    b.attach_kprobe(event=fnname_openat, fn_name="syscall__trace_entry_openat")
    b.attach_kretprobe(event=fnname_openat, fn_name="trace_return")

    if fnname_openat2:
        b.attach_kprobe(event=fnname_openat2, fn_name="syscall__trace_entry_openat2")
        b.attach_kretprobe(event=fnname_openat2, fn_name="trace_return")

initial_ts = 0

# header
if args.timestamp:
    print("%-14s" % ("TIME(s)"), end="")
if args.print_uid:
    print("%-6s" % ("UID"), end="")
print("%-6s %-16s %4s %3s " %
      ("TID" if args.tid else "PID", "COMM", "FD", "ERR"), end="")
if args.extended_fields:
    print("%-9s" % ("FLAGS"), end="")
print("PATH")

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    global initial_ts

    # split return value into FD and errno columns
    if event.ret >= 0:
        fd_s = event.ret
        err = 0
    else:
        fd_s = -1
        err = - event.ret

    if not initial_ts:
        initial_ts = event.ts

    if args.failed and (event.ret >= 0):
        return

    if args.name and bytes(args.name) not in event.comm:
        return

    if args.timestamp:
        delta = event.ts - initial_ts
        printb(b"%-14.9f" % (float(delta) / 1000000), nl="")

    if args.print_uid:
        printb(b"%-6d" % event.uid, nl="")

    printb(b"%-6d %-16s %4d %3d " %
           (event.id & 0xffffffff if args.tid else event.id >> 32,
            event.comm, fd_s, err), nl="")

    if args.extended_fields:
        printb(b"%08o " % event.flags, nl="")

    printb(b'%s' % event.fname)

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
start_time = datetime.now()
while not args.duration or datetime.now() - start_time < args.duration:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

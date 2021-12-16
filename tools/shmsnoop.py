#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# shmsnoop Trace shm*() syscalls.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: shmsnoop [-h] [-T] [-x] [-p PID] [-d DURATION] [-t TID] [-n NAME]
#
# Copyright (c) 2018 Jiri Olsa.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 08-Oct-2018   Jiri Olsa   Created this.

from __future__ import print_function
from bcc import ArgString, BPF
import argparse
from datetime import datetime, timedelta

# arguments
examples = """examples:
    ./shmsnoop           # trace all shm*() syscalls
    ./shmsnoop -T        # include timestamps
    ./shmsnoop -p 181    # only trace PID 181
    ./shmsnoop -t 123    # only trace TID 123
    ./shmsnoop -d 10     # trace for 10 seconds only
    ./shmsnoop -n main   # only print process names containing "main"
"""
parser = argparse.ArgumentParser(
    description="Trace shm*() syscalls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-t", "--tid",
    help="trace this TID only")
parser.add_argument("-d", "--duration",
    help="total duration of trace in seconds")
parser.add_argument("-n", "--name",
    type=ArgString,
    help="only print process names containing this name")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0
if args.duration:
    args.duration = timedelta(seconds=int(args.duration))

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>

struct val_t {
    u64            id;
    u64            ts;
    int            sys;
    unsigned long  key;
    unsigned long  size;
    unsigned long  shmflg;
    unsigned long  shmid;
    unsigned long  cmd;
    unsigned long  buf;
    unsigned long  shmaddr;
    unsigned long  ret;
    char           comm[TASK_COMM_LEN];
};

BPF_HASH(infotmp, u64, struct val_t);
BPF_PERF_OUTPUT(events);

enum {
    SYS_SHMGET,
    SYS_SHMAT,
    SYS_SHMDT,
    SYS_SHMCTL,
};

static int enter(struct val_t *val)
{
    u64 id  = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part

    FILTER

    val->id = id;
    infotmp.update(&id, val);
    return 0;
}

int trace_return(struct pt_regs *ctx)
{
    u64 id  = bpf_get_current_pid_tgid();
    u64 tsp = bpf_ktime_get_ns();
    struct val_t *val;

    val = infotmp.lookup(&id);
    if (val == 0)
        return 0;

    if (bpf_get_current_comm(&val->comm, sizeof(val->comm)) != 0)
        goto out;

    val->ts  = tsp / 1000;
    val->ret = PT_REGS_RC(ctx);
    events.perf_submit(ctx, val, sizeof(*val));

out:
    infotmp.delete(&id);
    return 0;
}

int syscall__shmget(struct pt_regs *ctx, u64 key, u64 size, u64 shmflg)
{
    struct val_t val = {
        .sys = SYS_SHMGET,
    };

    val.key    = key;
    val.size   = size;
    val.shmflg = shmflg;
    return enter(&val);
};

int syscall__shmat(struct pt_regs *ctx, u64 shmid, u64 shmaddr, u64 shmflg)
{
    struct val_t val = {
        .sys = SYS_SHMAT,
    };

    val.shmid   = shmid;
    val.shmaddr = shmaddr;
    val.shmflg  = shmflg;
    return enter(&val);
};

int syscall__shmdt(struct pt_regs *ctx, u64 shmaddr)
{
    struct val_t val = {
        .sys = SYS_SHMDT,
    };

    val.shmaddr = shmaddr;
    return enter(&val);
};

int syscall__shmctl(struct pt_regs *ctx, u64 shmid, u64 cmd, u64 buf)
{
    struct val_t val = {
        .sys = SYS_SHMCTL,
    };

    val.shmid = shmid;
    val.cmd   = cmd;
    val.buf   = buf;
    return enter(&val);
};

"""
if args.tid:  # TID trumps PID
    bpf_text = bpf_text.replace('FILTER',
        'if (tid != %s) { return 0; }' % args.tid)
elif args.pid:
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

syscall_fnname = b.get_syscall_fnname("shmget")
if BPF.ksymname(syscall_fnname) != -1:
    b.attach_kprobe(event=syscall_fnname, fn_name="syscall__shmget")
    b.attach_kretprobe(event=syscall_fnname, fn_name="trace_return")

syscall_fnname = b.get_syscall_fnname("shmat")
if BPF.ksymname(syscall_fnname) != -1:
    b.attach_kprobe(event=syscall_fnname, fn_name="syscall__shmat")
    b.attach_kretprobe(event=syscall_fnname, fn_name="trace_return")

syscall_fnname = b.get_syscall_fnname("shmdt")
if BPF.ksymname(syscall_fnname) != -1:
    b.attach_kprobe(event=syscall_fnname, fn_name="syscall__shmdt")
    b.attach_kretprobe(event=syscall_fnname, fn_name="trace_return")

syscall_fnname = b.get_syscall_fnname("shmctl")
if BPF.ksymname(syscall_fnname) != -1:
    b.attach_kprobe(event=syscall_fnname, fn_name="syscall__shmctl")
    b.attach_kretprobe(event=syscall_fnname, fn_name="trace_return")

TASK_COMM_LEN = 16    # linux/sched.h

SYS_SHMGET = 0
SYS_SHMAT  = 1
SYS_SHMDT  = 2
SYS_SHMCTL = 3

initial_ts = 0

# header
if args.timestamp:
    print("%-14s" % ("TIME(s)"), end="")
print("%-6s %-16s %6s %16s ARGs" %
      ("TID" if args.tid else "PID", "COMM", "SYS", "RET"))

def sys_name(sys):
    switcher = {
        SYS_SHMGET: "SHMGET",
        SYS_SHMAT:  "SHMAT",
        SYS_SHMDT:  "SHMDT",
        SYS_SHMCTL: "SHMCTL",
    }
    return switcher.get(sys, "N/A")

shmget_flags = [
  { 'name' : 'IPC_CREAT',     'value' :    0o1000 },
  { 'name' : 'IPC_EXCL',      'value' :    0o2000 },
  { 'name' : 'SHM_HUGETLB',   'value' :    0o4000 },
  { 'name' : 'SHM_HUGE_2MB',  'value' :  21 << 26 },
  { 'name' : 'SHM_HUGE_1GB',  'value' :  30 << 26 },
  { 'name' : 'SHM_NORESERVE', 'value' :   0o10000 },
  { 'name' : 'SHM_EXEC',      'value' :  0o100000 }
]

shmat_flags = [
  { 'name' : 'SHM_RDONLY', 'value' :  0o10000 },
  { 'name' : 'SHM_RND',    'value' :  0o20000 },
  { 'name' : 'SHM_REMAP',  'value' :  0o40000 },
  { 'name' : 'SHM_EXEC',   'value' : 0o100000 },
]

def shmflg_str(val, flags):
    cur = filter(lambda x : x['value'] & val, flags)
    str = "0x%x" % val

    if (not val):
        return str

    str += " ("
    cnt = 0
    for x in cur:
        if cnt:
            str += "|"
        str +=  x['name']
        val &= ~x['value']
        cnt += 1

    if val != 0 or not cnt:
        if cnt:
            str += "|"
        str += "0%o" % val

    str += ")"
    return str

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    global initial_ts

    if not initial_ts:
        initial_ts = event.ts

    if args.name and bytes(args.name) not in event.comm:
        return

    if args.timestamp:
        delta = event.ts - initial_ts
        print("%-14.9f" % (float(delta) / 1000000), end="")

    print("%-6d %-16s %6s %16lx " %
          (event.id & 0xffffffff if args.tid else event.id >> 32,
           event.comm.decode(), sys_name(event.sys), event.ret), end = '')

    if event.sys == SYS_SHMGET:
        print("key: 0x%lx, size: %lu, shmflg: %s" %
              (event.key, event.size, shmflg_str(event.shmflg, shmget_flags)))

    if event.sys == SYS_SHMAT:
        print("shmid: 0x%lx, shmaddr: 0x%lx, shmflg: %s" %
              (event.shmid, event.shmaddr, shmflg_str(event.shmflg, shmat_flags)))

    if event.sys == SYS_SHMDT:
        print("shmaddr: 0x%lx" % (event.shmaddr))

    if event.sys == SYS_SHMCTL:
        print("shmid: 0x%lx, cmd: %lu, buf: 0x%x" % (event.shmid, event.cmd, event.buf))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
start_time = datetime.now()
while not args.duration or datetime.now() - start_time < args.duration:
    try:
        b.perf_buffer_poll(timeout=1000)
    except KeyboardInterrupt:
        exit()

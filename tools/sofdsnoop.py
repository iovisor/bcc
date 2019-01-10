#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# sofdsnoop traces file descriptors passed via socket
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: sofdsnoop
#
# Copyright (c) 2018 Jiri Olsa.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 30-Jul-2018   Jiri Olsa   Created this.

from __future__ import print_function
from bcc import ArgString, BPF
import os
import argparse
import ctypes as ct
from datetime import datetime, timedelta

# arguments
examples = """examples:
    ./sofdsnoop           # trace file descriptors passes
    ./sofdsnoop -T        # include timestamps
    ./sofdsnoop -p 181    # only trace PID 181
    ./sofdsnoop -t 123    # only trace TID 123
    ./sofdsnoop -d 10     # trace for 10 seconds only
    ./sofdsnoop -n main   # only print process names containing "main"

"""
parser = argparse.ArgumentParser(
    description="Trace file descriptors passed via socket",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-t", "--tid",
    help="trace this TID only")
parser.add_argument("-n", "--name",
    type=ArgString,
    help="only print process names containing this name")
parser.add_argument("-d", "--duration",
    help="total duration of trace in seconds")
args = parser.parse_args()
debug = 0

ACTION_SEND=0
ACTION_RECV=1
MAX_FD=10

if args.duration:
    args.duration = timedelta(seconds=int(args.duration))

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <net/sock.h>

#define MAX_FD 10
#define ACTION_SEND   0
#define ACTION_RECV   1

struct val_t {
    u64  id;
    u64  ts;
    int  action;
    int  sock_fd;
    int  fd_cnt;
    int  fd[MAX_FD];
    char comm[TASK_COMM_LEN];
};

BPF_HASH(detach_ptr, u64, struct cmsghdr *);
BPF_HASH(sock_fd, u64, int);
BPF_PERF_OUTPUT(events);

static void set_fd(int fd)
{
    u64 id = bpf_get_current_pid_tgid();

    sock_fd.update(&id, &fd);
}

static int get_fd(void)
{
    u64 id = bpf_get_current_pid_tgid();
    int *fd;

    fd = sock_fd.lookup(&id);
    return fd ? *fd : -1;
}

static void put_fd(void)
{
    u64 id = bpf_get_current_pid_tgid();

    sock_fd.delete(&id);
}

static int sent_1(struct pt_regs *ctx, struct val_t *val, int num, void *data)
{
    val->fd_cnt = min(num, MAX_FD);

    if (bpf_probe_read(&val->fd[0], MAX_FD * sizeof(int), data))
        return -1;

    events.perf_submit(ctx, val, sizeof(*val));
    return 0;
}

#define SEND_1                                  \
    if (sent_1(ctx, &val, num, (void *) data))  \
        return 0;                               \
                                                \
    num -= MAX_FD;                              \
    if (num < 0)                                \
        return 0;                               \
                                                \
    data += MAX_FD;

#define SEND_2   SEND_1 SEND_1
#define SEND_4   SEND_2 SEND_2
#define SEND_8   SEND_4 SEND_4
#define SEND_260 SEND_8 SEND_8 SEND_8 SEND_2

static int send(struct pt_regs *ctx, struct cmsghdr *cmsg, int action)
{
    struct val_t val = { 0 };
    int *data, num, fd;
    u64 tsp = bpf_ktime_get_ns();

    data = (void *) ((char *) cmsg + sizeof(struct cmsghdr));
    num  = (cmsg->cmsg_len - sizeof(struct cmsghdr)) / sizeof(int);

    val.id      = bpf_get_current_pid_tgid();
    val.action  = action;
    val.sock_fd = get_fd();
    val.ts      = tsp / 1000;

    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) != 0)
        return 0;

    SEND_260
    return 0;
}

static bool allow_pid(u64 id)
{
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part

    FILTER

    return 1;
}

int trace_scm_send_entry(struct pt_regs *ctx, struct socket *sock, struct msghdr *hdr)
{
    struct cmsghdr *cmsg = NULL;

    if (!allow_pid(bpf_get_current_pid_tgid()))
        return 0;

    if (hdr->msg_controllen >= sizeof(struct cmsghdr))
        cmsg = hdr->msg_control;

    if (!cmsg || (cmsg->cmsg_type != SCM_RIGHTS))
        return 0;

    return send(ctx, cmsg, ACTION_SEND);
};

int trace_scm_detach_fds_entry(struct pt_regs *ctx, struct msghdr *hdr)
{
    struct cmsghdr *cmsg = NULL;
    u64 id = bpf_get_current_pid_tgid();

    if (!allow_pid(id))
        return 0;

    if (hdr->msg_controllen >= sizeof(struct cmsghdr))
        cmsg = hdr->msg_control;

    if (!cmsg)
        return 0;

    detach_ptr.update(&id, &cmsg);
    return 0;
};

int trace_scm_detach_fds_return(struct pt_regs *ctx)
{
    struct cmsghdr **cmsgp;
    u64 id = bpf_get_current_pid_tgid();

    if (!allow_pid(id))
        return 0;

    cmsgp = detach_ptr.lookup(&id);

    if (!cmsgp)
        return 0;

    return send(ctx, *cmsgp, ACTION_RECV);
}

int syscall__sendmsg(struct pt_regs *ctx, u64 fd, u64 msg, u64 flags)
{
    struct pt_regs p;

    if (!allow_pid(bpf_get_current_pid_tgid()))
        return 0;

    set_fd(fd);
    return 0;
}

int trace_sendmsg_return(struct pt_regs *ctx)
{
    if (!allow_pid(bpf_get_current_pid_tgid()))
        return 0;

    put_fd();
    return 0;
}

int syscall__recvmsg(struct pt_regs *ctx, u64 fd, u64 msg, u64 flags)
{
    struct pt_regs p;

    if (!allow_pid(bpf_get_current_pid_tgid()))
        return 0;

    fd = fd;

    set_fd(fd);
    return 0;
}

int trace_recvmsg_return(struct pt_regs *ctx)
{
    if (!allow_pid(bpf_get_current_pid_tgid()))
        return 0;

    put_fd();
    return 0;
}

"""

if args.tid:  # TID trumps PID
    bpf_text = bpf_text.replace('FILTER',
        'if (tid != %s) { return 0; }' % args.tid)
elif args.pid:
    bpf_text = bpf_text.replace('FILTER',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '')

# initialize BPF
b = BPF(text=bpf_text)

syscall_fnname = b.get_syscall_fnname("sendmsg")
if BPF.ksymname(syscall_fnname) != -1:
    b.attach_kprobe(event=syscall_fnname, fn_name="syscall__sendmsg")
    b.attach_kretprobe(event=syscall_fnname, fn_name="trace_sendmsg_return")

syscall_fnname = b.get_syscall_fnname("recvmsg")
if BPF.ksymname(syscall_fnname) != -1:
    b.attach_kprobe(event=syscall_fnname, fn_name="syscall__recvmsg")
    b.attach_kretprobe(event=syscall_fnname, fn_name="trace_recvmsg_return")

b.attach_kprobe(event="__scm_send", fn_name="trace_scm_send_entry")
b.attach_kprobe(event="scm_detach_fds", fn_name="trace_scm_detach_fds_entry")
b.attach_kretprobe(event="scm_detach_fds", fn_name="trace_scm_detach_fds_return")

TASK_COMM_LEN = 16    # linux/sched.h

initial_ts = 0

class Data(ct.Structure):
    _fields_ = [
        ("id",      ct.c_ulonglong),
        ("ts",      ct.c_ulonglong),
        ("action",  ct.c_int),
        ("sock_fd", ct.c_int),
        ("fd_cnt",  ct.c_int),
        ("fd",      ct.c_int  * MAX_FD),
        ("comm",    ct.c_char * TASK_COMM_LEN),
    ]

# header
if args.timestamp:
    print("%-14s" % ("TIME(s)"), end="")
print("%-6s %-6s %-16s %-25s %-5s %s" %
      ("ACTION", "TID", "COMM", "SOCKET", "FD", "NAME"))

def get_file(pid, fd):
    proc = "/proc/%d/fd/%d" % (pid, fd)
    try:
        return os.readlink(proc)
    except OSError as err:
        return "N/A"

# process event
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    tid = event.id & 0xffffffff;

    cnt = min(MAX_FD, event.fd_cnt);

    if args.name and bytes(args.name) not in event.comm:
        return

    for i in range(0, cnt):
        global initial_ts

        if not initial_ts:
            initial_ts = event.ts

        if args.timestamp:
            delta = event.ts - initial_ts
            print("%-14.9f" % (float(delta) / 1000000), end="")

        print("%-6s %-6d %-16s " %
              ("SEND" if event.action == ACTION_SEND else "RECV",
               tid, event.comm.decode()), end = '')

        sock = "%d:%s" % (event.sock_fd, get_file(tid, event.sock_fd))
        print("%-25s " % sock, end = '')

        fd = event.fd[i]
        fd_file = get_file(tid, fd) if event.action == ACTION_SEND else ""
        print("%-5d %s" % (fd, fd_file))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
start_time = datetime.now()
while not args.duration or datetime.now() - start_time < args.duration:
    try:
        b.perf_buffer_poll(timeout=1000)
    except KeyboardInterrupt:
        exit()

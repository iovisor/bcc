#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# fdleak    Trace and display over-threshold fds to detect FD leaks process.
#           All FD allocate will be traced, if the threshold is exceeded or 
#           EMFILE occurs, then will be recorded by the monitoring program.
#
#           `In UNIX, everything is a file`, file leakage problems may 
#           occur when most resources are used improperly, eg:
#             file, socket, eventfd, pipe, ashmem, dmabuf, syncfence ...
#
#           It's a light and easy to use ebpf probe fd alloc and monitor 
#           over-threshold fds process, collects stack and list open files.
#
# USAGE: fdleak [-h] [-p PID] [-w WARN] [--dumpstack] [--lsof] [-a]
#
# Licensed under the Apache License, Version 2.0 (the "License")
# Copyright (c) 2021 Vachel Yang.
# 11-Oct-2021    Vachel.Yang    Created this.

from bcc import BPF
from bcc.utils import printb
from datetime import datetime
import argparse,sys,os

# arguments
examples = """examples:
    ./fdleak                # trace all process alloc_fd()
    ./fdleak -p 181         # only trace PID 181
    ./fdleak -w 900         # set warning threshold 900
    ./fdleak --dumpstack    # show alloc fd stack
    ./fdleak --lsof         # show open files
    ./fdleak -a             # show all debug info
"""

parser = argparse.ArgumentParser(
    description="Trace FD leak",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
                    help="trace this PID only")
parser.add_argument("-w", "--warn",
                    help="set warning threshold,default is 819(1024*0.8)")
parser.add_argument("--dumpstack",default=False, action="store_false", dest="dumpstack",
                    help="show alloc fd stack")
parser.add_argument("--lsof",default=False, action="store_false", dest="lsof",
                    help="list of open files")

parser.add_argument("-a", "--showall",default=False, action="store_false",
                    help="show all debug info")
args = parser.parse_args()

if args.showall:
    args.lsof=True
    args.dumpstack=True

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>
#include <asm-generic/errno-base.h>
#include <linux/fdtable.h>
#include <linux/sched.h>

BPF_PERF_OUTPUT(events);
// 8k buf
BPF_STACK_TRACE(kernel_stack, 8192);
// 8k buf
BPF_STACK_TRACE(user_stack, 8192);

struct data_t {
    char taskname[TASK_COMM_LEN];
    int pid;
    int fds;
    int stack_user;
    int stack_kernel;
};

inline static void submit_to_user(int fds,struct pt_regs *ctx){
    struct data_t data = {0};
    data.pid = bpf_get_current_pid_tgid();
    data.fds = fds;
    bpf_get_current_comm(&data.taskname, sizeof(data.taskname));
    data.stack_user = user_stack.get_stackid(ctx, BPF_F_USER_STACK | BPF_F_REUSE_STACKID);
    data.stack_kernel = kernel_stack.get_stackid(ctx, 0);
    events.perf_submit(ctx, &data, sizeof(data));
}

int kretprobe____alloc_fd(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);

    const int FILTER_THRESHOLD = ##FILTER_THRESHOLD## ;
    ##FILTER_PID##
    if (ret <= 0) {
        if(ret == -EMFILE){
          submit_to_user(ret,ctx);
        }
        return 0;
    }

    if(ret > FILTER_THRESHOLD){
        submit_to_user(ret,ctx);
    }

    return 0;
}

"""
DEFAULT_MAX_FD = 1024
FILTER_THRESHOLD = (int)(DEFAULT_MAX_FD*0.8)

# parse arguments

if args.pid:
    bpf_text = bpf_text.replace('##FILTER_PID##',
                                'if (bpf_get_current_pid_tgid() != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('##FILTER_PID##', '')

if args.warn:
    bpf_text = bpf_text.replace('##FILTER_THRESHOLD##',
                                '%s' % args.warn)
else:
    bpf_text = bpf_text.replace(
        '##FILTER_THRESHOLD##', '%s' % FILTER_THRESHOLD)

# load c text
b = BPF(text=bpf_text)

def list_open_file(event):
    cmd = 'ls -al /proc/%d/fd' % event.pid
    # f=os.popen(cmd)
    # print(f.read())
    os.system(cmd)


def dump_stack_user(event):
    print("user")
    for addr in b["user_stack"].walk(event.stack_user):
        print("\t%s" % b.sym(addr, event.pid, show_module=True, show_offset=True))

def dump_stack_kernel(event):
    print("kernel")
    for addr in b["kernel_stack"].walk(event.stack_kernel):
        print("\t%s" % b.ksym(addr, event.pid, show_offset=True))

process = {}

def print_event(cpu, data, size):
    alloc_info = {}
    user_stack = b["user_stack"]
    kernel_stack = b["kernel_stack"]
    event = b["events"].event(data)

    print("\n------------------------------------------------------")
    print("%-10s %-16s %-6s %3s" % ("TIME", "COMM", "PID", "FDs"))
    printb(b"[%s] %-16s %-6d %3d" % (datetime.now().strftime("%H:%M:%S"),
                                     event.taskname, event.pid, event.fds))
    if args.dumpstack:
        print("dump stack:")
        dump_stack_user(event)
        dump_stack_kernel(event)
    if args.lsof and (event.pid not in process):
        list_open_file(event)
        process[event.pid]=1

b['events'].open_perf_buffer(print_event)
print("Trace and display over-threshold fds to detect FD leaks process, ctrl-c to exit.")

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    sys.exit()


#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# fdleak  Trace and display fd alloc/close to detect FD leaks in user-mode processes.
#         If the survival time is longer than the minimum allowable survival time,
#         or EMFILE occurs, the tool will collects allocator user-stack,max fd number,
#         thread name, tid..
#
#         `In UNIX, everything is a file`, file leakage problems may
#         occur when most resources are used improperly, eg:
#           file, socket, eventfd, pipe, ashmem, dmabuf, syncfence ...
#
# USAGE: fdleak [-h] [-p PID] [-w WARN] [--dumpstack] [--lsof] [-a]
#
# Licensed under the Apache License, Version 2.0 (the "License")
# Copyright (c) 2021 Vachel Yang.
# 16-Oct-2021    Vachel.Yang    Created this.

from ctypes import c_int
from bcc import BPF
from datetime import datetime
from time import sleep
import argparse
import sys
import os

# arguments
examples = """examples:
    ./fdleak                # trace all process alloc/close file descriptor
    ./fdleak -p 181         # only trace PID 181
    ./fdleak --lsof         # list the files opened by the monitor process
    ./fdleak -i 10          # interval to scan for outstanding allocations (in seconds), default is 5s
    ./fdleak -m 60          # minimum allowable survival time (in seconds), default is 30s
"""

parser = argparse.ArgumentParser(
    description="Trace FD leak",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", default=-1, help="trace this PID only")
parser.add_argument("--lsof", default=False, action="store_true", dest="lsof",
                    help="list the files opened by the monitor process")
parser.add_argument("-i", "--interval", default=5, type=int,
                    help="interval (in seconds) to scan for outstanding allocations")
parser.add_argument("-m", "--min_allow", default=30, type=int,
                    help="minimum allowable survival time")
parser.add_argument("-D", "--debug", default=False, action="store_true",
                    help="print debug message, only for developer")
parser.add_argument("--ebpf", action="store_true",
                    help=argparse.SUPPRESS)
args = parser.parse_args()

bpf_text = """
#include <asm-generic/errno-base.h>
#include <bcc/proto.h>
#include <linux/fdtable.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

struct alloc_info_t {
  u64 timestamp_ns;
  int stack_id;
  u32 tid;
  int fd;
  char comm[TASK_COMM_LEN];
};

struct combined_alloc_info_t {
  u64 last_longest_survivor;
  int number_of_allocs;
};

BPF_STACK_TRACE(user_stack, 10240);
BPF_HASH(fd_allocs_hash, u64, struct alloc_info_t, 1024000);
BPF_HASH(combined_allocs_hash, int, struct combined_alloc_info_t, 10240);

// Programs that rely on the system `exit_files`are not considered
// However, their fd is generally less than NR_OPEN_DEFAULT
#define FD_MONITOR_TRIGGER(fd)        \
  if (fd > 0 && fd < NR_OPEN_DEFAULT) \
    return 0;

static inline void update_statistics_add(int stack_id) {
  struct combined_alloc_info_t *existing_cinfo;
  struct combined_alloc_info_t cinfo = {0};

  existing_cinfo = combined_allocs_hash.lookup(&stack_id);
  if (existing_cinfo != NULL)
    cinfo = *existing_cinfo;

  cinfo.number_of_allocs += 1;

  combined_allocs_hash.update(&stack_id, &cinfo);
}

static inline int fd_alloc_return(struct pt_regs *ctx) {
  int ret_fd = PT_REGS_RC(ctx);

  struct alloc_info_t info = {0};
  u64 pidfd = bpf_get_current_pid_tgid() & 0xffffffff00000000L;
  u32 tid = (u32)(bpf_get_current_pid_tgid() & 0xffffffffL);
  struct combined_alloc_info_t *cinfo;

  //other errors are not the monitor focus
  if(ret_fd < 0 && ret_fd != -EMFILE)
    return 0;

  pidfd += (u32)ret_fd;
  info.timestamp_ns = bpf_ktime_get_ns();
  info.stack_id =
      user_stack.get_stackid(ctx, BPF_F_USER_STACK | BPF_F_REUSE_STACKID);
  info.tid = tid;
  info.fd = ret_fd;
  bpf_get_current_comm(info.comm, TASK_COMM_LEN);

  fd_allocs_hash.update(&pidfd, &info);
  update_statistics_add(info.stack_id);

  ##PRINT_DEBUG##
  bpf_trace_printk("[%s-%u] alloc fd[%d] entered \\n",
                    info.comm, info.tid, ret_fd);

  return 0;
}

static inline void update_statistics_del(int stack_id, u64 survivor_time_ns) {
  struct combined_alloc_info_t *existing_cinfo;
  struct combined_alloc_info_t cinfo = {0};

  existing_cinfo = combined_allocs_hash.lookup(&stack_id);
  if (existing_cinfo == NULL) {
    bpf_trace_printk("[ERROR] missed statistics add %d\\n", stack_id);
    return;
  }
  cinfo = *existing_cinfo;

  if (cinfo.number_of_allocs > 0)
    cinfo.number_of_allocs--;

  if (survivor_time_ns > cinfo.last_longest_survivor) {
    cinfo.last_longest_survivor = survivor_time_ns;
  }

  combined_allocs_hash.update(&stack_id, &cinfo);
}

static inline int fd_close_enter(unsigned fd) {
  u64 pidfd = bpf_get_current_pid_tgid() & 0xffffffff00000000L;
  struct alloc_info_t *info;
  u64 survivor_time_ns = bpf_ktime_get_ns();

  pidfd += (u32)fd;

  info = fd_allocs_hash.lookup(&pidfd);
  if (info == 0) {
    return 0;
  }

  survivor_time_ns -= info->timestamp_ns;
  ##PRINT_DEBUG##
  bpf_trace_printk("[%s-%u] free fd[%d] entered \\n",
                    info->comm, info->tid, fd);

  fd_allocs_hash.delete(&pidfd);
  update_statistics_del(info->stack_id, survivor_time_ns);

  return 0;
}

// close fd
// https://github.com/torvalds/linux/commit/8760c909f54a82aaa6e76da19afe798a0c77c3c3
// file: Rename __close_fd to close_fd and remove the files parameter
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
int kprobe____close_fd(struct pt_regs *ctx, unsigned fd)
#else
int kprobe__close_fd(struct pt_regs *ctx, unsigned int fd)
#endif
{
  ##FILTER_PID##
  FD_MONITOR_TRIGGER(fd)
  return fd_close_enter(fd);
}

// alloc_fd
int kretprobe__get_unused_fd_flags(struct pt_regs *ctx)
{
  ##FILTER_PID##
  int fd = PT_REGS_RC(ctx);
  FD_MONITOR_TRIGGER(fd)

  return fd_alloc_return(ctx);
}
"""
# parse arguments
if args.pid != -1:
    bpf_text = bpf_text.replace('##FILTER_PID##',
        'if (bpf_get_current_pid_tgid() >> 32 != %s) { return 0; }' % args.pid)
    print("start trace pid= %s" % args.pid)
else:
    bpf_text = bpf_text.replace('##FILTER_PID##', '')

interval = args.interval
min_allow_survival = args.min_allow

if args.debug:
    bpf_text = bpf_text.replace("##PRINT_DEBUG##", "if(1)")
else:
    bpf_text = bpf_text.replace("##PRINT_DEBUG##", "if(0)")

if args.ebpf:
    print(bpf_text)

# load c text
bpf = BPF(text=bpf_text)

def get_pname(id):
    comm_path=("/proc/%d/comm"%id)
    return open(comm_path, 'r').readline().rstrip('\n')
    
class Allocation(object):
    def __init__(self, p_name, pid, t_name, tid, fd, stack, survival_time):
        t = t_name+"-"+str(tid)
        self.thread = {t}
        self.p_name = p_name+("-%d"%pid)
        self.fd = [fd]
        self.stack = stack
        self.max_survival_time = survival_time
        self.limit = self.get_file_limit()

    def update(self, t_name, tid, fd, survival_time):
        t = t_name+"-"+str(tid)
        self.thread.add(t)
        self.fd.append(fd)
        self.max_survival_time = max(survival_time, self.max_survival_time)

    def get_max_survival_time(self):
        return self.max_survival_time

    def get_max_fd(self):
        # -24 is EMFILE, most of the time it means too many open files
        if(self.fd.count(-24) > 0):
            return "\033[1;31m-24\033[0m %d" % max(self.fd)
        else:
            return max(self.fd)

    def get_file_limit(self):
        value = open("/proc/sys/fs/file-max", 'r').readline().rstrip('\n')
        # too big number is unsightly
        if value != 'unlimited' and int(value) > 0xffff:
            value = 'unlimited'
        return value


def list_open_file(pid):
    cmd = 'ls -al /proc/%d/fd' % pid
    os.system(cmd)


def find_allocinfo_by_stack_id(in_stack_id, in_num_allocs):
    fd_allocs_hash = sorted(bpf["fd_allocs_hash"].items(),
                            key=lambda a: a[1].timestamp_ns)
    stack_traces = bpf["user_stack"]

    process_alloc_dic = {}
    stack_max_survivor = 0
    for pidfd, alloc_info in fd_allocs_hash:
        if alloc_info.stack_id == in_stack_id:
            tid = alloc_info.tid
            fd = alloc_info.fd
            survival_time = 1+((int)(BPF.monotonic_time() -
                                     alloc_info.timestamp_ns)/1000000000)
            pid = int(pidfd.value >> 32)
            is_sym_normal = 0

            if pid not in process_alloc_dic:
                bt = list(stack_traces.walk(in_stack_id))
                stack = []
                for addr in bt:
                    func = bpf.sym(addr, pid, show_module=True,
                                   show_offset=True)
                    if (func != "[unknown]"):
                        is_sym_normal = 1
                    stack.append(func)

                if is_sym_normal > 0:
                    process_alloc_dic[pid] = Allocation(get_pname(pid), 
                        pid, alloc_info.comm, tid, fd, stack, survival_time)
            else:
                process_alloc_dic[pid].update(
                    alloc_info.comm, tid, fd, survival_time)
            if is_sym_normal > 0:
                stack_max_survivor = process_alloc_dic[pid].get_max_survival_time(
                )

    if process_alloc_dic and stack_max_survivor > min_allow_survival:
        print("[%s] stack id-%d in \033[1;31m%d\033[0m allocations from stack" %
              (datetime.now().strftime("%H:%M:%S"), in_stack_id, in_num_allocs))
        print("\t %-20s %-9s %-15s %-8s %-7s %s" %
              ("PNAME-PID", "LIMIT",
               "MAX_SURVIVAL(s)", "MAX_FD", "THREADs", "NAME-TID list"))
        for p, alloc in process_alloc_dic.items():
            print("\t %-20s %-9s %-15s %-8s %-7s %s\n\t Backtrace:"
                  % (alloc.p_name, alloc.limit, alloc.max_survival_time, process_alloc_dic[p].get_max_fd(),
                     len(alloc.thread), " / ".join(str(t) for t in alloc.thread)))
            print("\t %s" % (b"\n\t ".join(alloc.stack).decode("ascii")))
            if args.lsof:
                list_open_file(p)


def print_outstanding_combined():
    combined_allocs = sorted(bpf["combined_allocs_hash"].items(),
                             key=lambda a: a[1].number_of_allocs)

    for stack_id, combined_info in combined_allocs:
        if combined_info.number_of_allocs > 2:
            find_allocinfo_by_stack_id(
                stack_id.value, combined_info.number_of_allocs)


print("Trace and display fd alloc/close to detect FD leaks process, ctrl-c to exit.")
while True:
    try:
        sleep(interval)
    except KeyboardInterrupt:
        exit()
    print_outstanding_combined()
    if args.debug:
        print(bpf.trace_fields())
    sys.stdout.flush()

#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# fdleak    Trace and display fd alloc/close to detect FD leaks in user-mode
#           processes.
#           For Linux, uses BCC,BPF. Embedded C.
#
# USAGE: fdleak [-h] [-p PID] [-w WARN] [--dumpstack] [--lsof] [-a]
#
# If the survival time is longer than the minimum allowable survival time,
# and the fd number opened by the process is keeps growing,that will trigger
# fdleak to collect allocator information: user stack, max fd number,
# thread name, tid.
#
# This tool only works on Linux 4.6+.
#
# # Copyright (c) 2021 Vachel Yang.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 16-Oct-2021    Vachel.Yang    Created this.
# 19-Oct-2021    Vachel.Yang    Add man8,readme
# 19-Oct-2021    Vachel.Yang    Add `exit_files` monitor and top-fd growth

from ctypes import c_int
from bcc import BPF
from datetime import datetime
from time import sleep
import argparse
import sys
import os

# arguments
examples = """
EXAMPLES:

./fdleak
        Trace all process alloc/close file descriptor.
        default internal inspection frequency is 5 seconds,
        default minimim allowable survival time is 30 seconds.
./fdleak -p $(pidof allocs)
        Only monitor the allocation and close files of filtered pid
./fdleak --lsof
        List the files opened by the monitor process
./fdleak -i 60
        Set the internal inspection frequency to 60 seconds
./fdleak -m 60
        Set the minimum allowable survival time to 60 seconds
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
  u32 pid;
};

struct combined_alloc_info_t {
  //TODO Determine whether the same stack has different survival times
  u64 last_longest_survivor;
  int number_of_allocs;
};

BPF_STACK_TRACE(user_stack, 102400);
BPF_HASH(pidfd_allocs_hash, u64, struct alloc_info_t, 102400);
BPF_HASH(combined_allocs_hash, int, struct combined_alloc_info_t, 10240);
//TODO
BPF_HASH(pid_exit_hash, int, u8, 10240);

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

static inline void clear_pid_exit_flag(){
  int pid = bpf_get_current_pid_tgid()>>32;
  u8 is_exit = 0;
  pid_exit_hash.update(&pid, &is_exit);
}

static inline void set_pid_exit_flag(){
  int pid = bpf_get_current_pid_tgid()>>32;
  u8 is_exit = 1;
  pid_exit_hash.update(&pid, &is_exit);
}

static inline int fd_alloc_return(struct pt_regs *ctx) {
  int ret_fd = PT_REGS_RC(ctx);
  struct alloc_info_t info = {0};
  u64 pidfd = bpf_get_current_pid_tgid() & 0xffffffff00000000L;
  u32 pid = bpf_get_current_pid_tgid()>>32;
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
  info.pid = pid;

  clear_pid_exit_flag();
  pidfd_allocs_hash.update(&pidfd, &info);
  update_statistics_add(info.stack_id);
  ##PRINT_DEBUG##
  bpf_trace_printk("[%u] alloc fd[%d] entered \\n",info.tid, ret_fd);
  return 0;
}

static inline void update_statistics_del(int stack_id,
                                         u64 survivor_time_ns) {
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
  info = pidfd_allocs_hash.lookup(&pidfd);
  if (info == 0) {
    return 0;
  }
  survivor_time_ns -= info->timestamp_ns;
  ##PRINT_DEBUG##
  bpf_trace_printk("[%u] free fd[%d] entered \\n",info->tid, fd);
  pidfd_allocs_hash.delete(&pidfd);
  update_statistics_del(info->stack_id, survivor_time_ns);

  return 0;
}

// close fd
// https://github.com/torvalds/linux/commit/8760c90
// file: Rename __close_fd to close_fd and remove the files parameter
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
int kprobe____close_fd(struct pt_regs *ctx, struct files_struct *files,
                       unsigned fd)
#else
int kprobe__close_fd(struct pt_regs *ctx, struct files_struct *files,
                     unsigned int fd)
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

// do_exit
int kprobe__exit_files(struct pt_regs* ctx){
    ##FILTER_PID##
    set_pid_exit_flag();
    return 0;
}
"""
# parse arguments
if args.pid != -1:
    bpf_text = bpf_text.replace('##FILTER_PID##',
        'if (bpf_get_current_pid_tgid() >> 32 != %s) { return 0; }'
        % args.pid)
    print("start trace pid= %s" % args.pid)
else:
    bpf_text = bpf_text.replace('##FILTER_PID##', '')

interval = args.interval
min_allow_survival = args.min_allow
min_allow_ns = min_allow_survival * 1000000000

if args.debug:
    bpf_text = bpf_text.replace("##PRINT_DEBUG##", "if(1)")
else:
    bpf_text = bpf_text.replace("##PRINT_DEBUG##", "if(0)")

if args.ebpf:
    print(bpf_text)

# load c text
bpf = BPF(text=bpf_text)


def get_pname(id):
    try:
        comm_path = ("/proc/%d/comm" % id)
        pname = open(comm_path, 'r').readline().rstrip('\n')
    except Exception:
        pname = "Unknow"
    return pname


def get_tname(pid, tid):
    try:
        comm_path = ("/proc/%d/task/%d/comm" % (pid, tid))
        tname = open(comm_path, 'r').readline().rstrip('\n')
    except Exception:
        tname = "Unknow"
    return tname


class Allocation(object):
    def __init__(self, pid):
        self.thread = []
        self.pid = pid
        self.p_name = get_pname(pid) + ("-%d" % pid)
        self.fd = []
        self.max_survival_time = 0
        self.limit = self.get_file_limit()
        self.stack = []

    def update(self, tid, fd, survival_time):
        t = get_tname(self.pid, tid) + "-" + str(tid)
        self.thread.append(t)
        self.fd.append(fd)
        self.max_survival_time = max(survival_time, self.max_survival_time)

    def update_stack(self, stack):
        self.stack.append(stack)

    def get_maxfd(self):
        return max(self.fd)

    def get_max_survival_time(self):
        return self.max_survival_time

    def show_fd(self):
        # -24 is EMFILE, most of the time it means too many open files
        if(self.fd.count(-24) > 0):
            return "\033[1;31m-24\033[0m %d" % self.get_maxfd()
        else:
            return self.get_maxfd()

    def get_file_limit(self):
        value = open("/proc/sys/fs/file-max", 'r').readline().rstrip('\n')
        # too big number is unsightly
        if value != 'unlimited' and int(value) > 0xffff:
            value = 'unlimited'
        return value


def list_open_file(pid):
    try:
        f = os.popen('ls -al /proc/%d/fd' % pid)
    except Exception:
        return "Unknow"
    return f.read()


def is_process_exited(pid):
    pid_exit_list = bpf["pid_exit_hash"].items()
    for p, e in pid_exit_list:
        if pid == p.value and 1 == e.value:
            return True
    return False


def get_stack_symol_by_id(stack_id, pid):
    stack_traces = bpf["user_stack"]
    bt = []
    for addr in stack_traces.walk(stack_id.value):
        sym = bpf.sym(addr, pid, show_module=True, show_offset=True)
        bt.append(sym)
    return bt


top_fd = {}


def find_allocinfo_by_stack_id(in_stack_id):
    pidfd_allocs_hash = bpf["pidfd_allocs_hash"].items()
    stack_traces = bpf["user_stack"]
    process_alloc_dic = {}

    for k, alloc_info in pidfd_allocs_hash:
        if alloc_info.stack_id == in_stack_id:
            if(BPF.monotonic_time() - alloc_info.timestamp_ns < min_allow_ns):
                continue
            survival_time = 1 + ((int)(
                BPF.monotonic_time() - alloc_info.timestamp_ns) / 1000000000)
            tid = alloc_info.tid
            fd = alloc_info.fd
            pid = alloc_info.pid
            if is_process_exited(pid):
                if pid in process_alloc_dic:
                    process_alloc_dic.pop(pid)
                if pid in top_fd:
                    top_fd.pop(pid)
                continue
            if pid not in process_alloc_dic:
                process_alloc_dic[pid] = Allocation(pid)
            process_alloc_dic[pid].update(tid, fd, survival_time)
    # Determine whether it is greater than the fd number of the last scan
    for p, alloc in process_alloc_dic.items():
        if(p not in top_fd):
            process_alloc_dic.pop(p)
            top_fd[p] = alloc.get_maxfd()
        elif(alloc.get_maxfd() > top_fd[p]):
            top_fd[p] = alloc.get_maxfd()
            bt = list(stack_traces.walk(in_stack_id))
            for addr in bt:
                alloc.update_stack(
                    bpf.sym(addr, pid, show_module=True, show_offset=True))
        else:
            process_alloc_dic.pop(p)

    return process_alloc_dic


def print_outstanding_combined():
    combined_allocs = sorted(bpf["combined_allocs_hash"].items(),
                             key=lambda a: -a[1].number_of_allocs)

    for stack_id, combined_info in combined_allocs:
        if combined_info.number_of_allocs > 0:
            process_alloc_dic = find_allocinfo_by_stack_id(stack_id.value)
            if(process_alloc_dic):
                print("[%s] stack id-%d in \033[1;31m%d\033[0m allocations \
                    from stack" %
                      (datetime.now().strftime("%H:%M:%S"),
                       stack_id.value, combined_info.number_of_allocs))
                print("\t %-20s %-9s %-15s %-8s %-7s %s" %
                      ("PNAME-PID", "LIMIT",
                       "MAX_SURVIVAL(s)", "MAX_FD", "THREADs",
                       "NAME-TID list"))
                for p, alloc in process_alloc_dic.items():
                    print(("\t %-20s %-9s %-15s %-8s %-7s %s\n\t Backtrace:"
                           % (alloc.p_name, alloc.limit,
                           alloc.max_survival_time, alloc.show_fd(),
                           len(alloc.thread),
                           " / ".join(str(t) for t in alloc.thread))))
                    print("\t %s" % (b"\n\t "
                           .join(alloc.stack).decode("ascii")))
                    if args.lsof:
                        print(list_open_file(p))


print(
"Trace and display fd alloc/close to detect FD leaks process, ctrl-c to exit.")
while True:
    try:
        sleep(interval)
    except KeyboardInterrupt:
        exit()
    print_outstanding_combined()
    if args.debug:
        print(bpf.trace_fields())
    sys.stdout.flush()

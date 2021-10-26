#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# fdleak    Trace and display fd alloc/close to detect FD leaks processes.
#           For Linux, uses BCC,BPF. Embedded C.
#
# USAGE: fdleak.py [-h] [-p PID] [--csv] [--lsof] [-i INTERVAL]
#
# Fdleak divided into 3 stages: loose L1, loose L2, strict L3
# The first two stages check whether the allocation number of fd has been
# increasing (for processes). If it keeps increasing, strict mode will be
# triggered,strictly check the time of each allocation and close. If the
# survivor is greater than 30s, strict inspection will print out the
# monitored Process name, PID, Thread name, TID, Backtrace, Trace Hits
#
# This tool only works on Linux 4.6+.
# The dump and plot argument need installed pandas and matplotlib module.
#
# # Copyright (c) 2021 Vachel Yang.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 16-Oct-2021    Vachel.Yang    Created this.
# 19-Oct-2021    Vachel.Yang    Add man8,readme
# 19-Oct-2021    Vachel.Yang    Add `exit_files` monitor and top-fd growth
# 26-Oct-2021    Vachel.Yang    Add loose mode and strict mode

from bcc import BPF
from datetime import datetime
from time import sleep
import argparse
import sys
import os
import traceback
import resource
import platform


class Probe(object):
    def __init__(self, pid=-1, ebpf=None):
        self.pid = pid
        self.ebpf = ebpf
        self.text_comm = """
        #include <asm-generic/errno-base.h>
        #include <bcc/proto.h>
        #include <linux/fdtable.h>
        #include <linux/sched.h>
        #include <uapi/linux/ptrace.h>
        """

        self.text_loose_entry = """
        BPF_HASH(pid_count_hash, u32, int, 102400);
        static inline int loose_fd_alloc(){
            ##FILTER_PID##
            u32 tgid = bpf_get_current_pid_tgid()>>32;
            int* fd_p = pid_count_hash.lookup(&tgid);
            if (fd_p == NULL) {
                // if the map for the key doesn't exist, create one
                int init_one = 1;
                pid_count_hash.update(&tgid, &init_one);
            }else {
                *fd_p+=1;
            }
            return 0;
        }

        static inline int loose_fd_close(){
            ##FILTER_PID##
            u32 tgid = bpf_get_current_pid_tgid()>>32;
            int* fd_p = pid_count_hash.lookup(&tgid);
            if (fd_p == 0) return 0;
            // FD allocation before fdleak monitoring is not recorded
            if(*fd_p > 0){*fd_p-=1;}
            return 0;
        }
        """

        self.strict_entry = """
        struct alloc_info_t {
            u32 timestamp;
            int user_stack;
            int kernel_stack;
            u32 tid;
            int fd;
            u32 pid;
        };

        BPF_STACK_TRACE(stack_trace, 102400);
        BPF_HASH(pidfd_allocs_hash, u64, struct alloc_info_t, 102400);

        static inline int fd_alloc_return(struct pt_regs *ctx){
            ##FILTER_PID##
            int ret_fd = PT_REGS_RC(ctx);
            struct alloc_info_t info = {0};
            u64 pidfd = bpf_get_current_pid_tgid() & 0xffffffff00000000L;
            struct combined_alloc_info_t *cinfo;
            //other errors are not the monitor focus
            if(ret_fd < 0) return 0;
            pidfd += (u32)ret_fd;
            info.timestamp = bpf_ktime_get_ns()/1000000000;
            info.user_stack = stack_trace.get_stackid(ctx,\
                BPF_F_USER_STACK | BPF_F_REUSE_STACKID);
            info.kernel_stack =
                stack_trace.get_stackid(ctx, 0);
            info.tid = (u32)(bpf_get_current_pid_tgid() & 0xffffffffL);
            info.fd = ret_fd;
            info.pid = bpf_get_current_pid_tgid()>>32;
            pidfd_allocs_hash.update(&pidfd, &info);
            return 0;
        }

        static inline int fd_close_enter(unsigned fd){
            ##FILTER_PID##
            u64 pidfd = bpf_get_current_pid_tgid() & 0xffffffff00000000L;
            struct alloc_info_t *info;
            pidfd += (u32)fd;
            info = pidfd_allocs_hash.lookup(&pidfd);
            if (info == NULL) return 0;
            pidfd_allocs_hash.delete(&pidfd);;
            return 0;
        }
        """
        self.text_func = """
        int ##FUC##___close_fd(struct pt_regs *ctx, struct files_struct *files,
                                unsigned fd){
            ##CLOSE_ENTRY##
        }

        int ##FUC##_close_fd(struct pt_regs *ctx, unsigned int fd){
            ##CLOSE_ENTRY##
        }

        int ##FUC##___close_range(struct pt_regs *ctx, unsigned int fd){
            ##CLOSE_ENTRY##
        }

        int ##FUC##_close_fd_get_file(struct pt_regs *ctx, unsigned int fd){
            ##CLOSE_ENTRY##
        }

        int ##FUC##_filp_close(struct pt_regs *ctx){
            int fd = 0;
            ##CLOSE_ENTRY##
        }

        int ##FUC##_put_unused_fd(struct pt_regs *ctx, unsigned int fd){
            ##CLOSE_ENTRY##
        }

        // alloc fd
        int ##FUC##_get_unused_fd_flags(struct pt_regs *ctx){
            ##ALLOC_ENTRY##
        }

        int ##FUC##_f_dupfd(struct pt_regs *ctx){
            ##ALLOC_ENTRY##
        }
        """

    def load_strict(self, target_list):
        s = 'if( 1'
        for p in target_list:
            s += ('&&(bpf_get_current_pid_tgid() >> 32 != %s)' % p)
        s += '){return 0;}'
        text_entry = self.strict_entry.replace('##FILTER_PID##', s)
        text_func = self.text_func.replace('##FUC##', 'strict')
        text_func = text_func.replace(
            '##CLOSE_ENTRY##',
            'return fd_close_enter(fd);'
        )

        text_func = text_func.replace(
            '##ALLOC_ENTRY##',
            'return fd_alloc_return(ctx);'
        )
        text_bpf = self.text_comm + text_entry + text_func
        if self.ebpf:
            print(text_bpf)
        self.strict_bpf = BPF(text=text_bpf)

    def load_loose(self):
        if self.pid != -1:
            self.text_loose_entry = self.text_loose_entry.replace(
                '##FILTER_PID##',
                'if (bpf_get_current_pid_tgid() >> 32 != %s) { return 0; }'
                % self.pid)
            print("start trace pid= %s" % self.pid)
        else:
            self.text_loose_entry = self.text_loose_entry.replace(
                '##FILTER_PID##', '')
        text_func = self.text_func.replace('##FUC##', 'loose')
        text_func = text_func.replace(
            '##CLOSE_ENTRY##', 'return loose_fd_close();')
        text_func = text_func.replace(
            '##ALLOC_ENTRY##',
            'int fd = PT_REGS_RC(ctx);if(fd < 0) return 0;\
                return loose_fd_alloc();'
        )
        text_bpf = (self.text_comm + self.text_loose_entry)\
            + text_func
        if self.ebpf:
            print(text_bpf)
        self.bpf = BPF(text=text_bpf)

    def attach_common(self, b, FUNC):
        b.attach_kprobe(event="put_unused_fd",
                        fn_name=FUNC + '_put_unused_fd')
        if platform.release() > "5.11.0":
            b.attach_kprobe(event="__close_range",
                            fn_name=FUNC + '___close_range')
            b.attach_kprobe(event="close_fd_get_file",
                            fn_name=FUNC + '_close_fd_get_file')
        b.attach_kretprobe(event="get_unused_fd_flags",
                            fn_name=FUNC + '_get_unused_fd_flags')
        b.attach_kretprobe(event="f_dupfd", fn_name=FUNC + '_f_dupfd')

    def attach_loose(self):
        self.bpf.attach_kprobe(event="filp_close", fn_name="loose_filp_close")
        self.attach_common(self.bpf, 'loose')

    def attach_strict(self):
        """
        In the scenario where call 'filp_close' to close fd but not call
        'close_fd',it just detect in loose check, but strict check not
        detect that fd is closed.
        for example, redirect the file to '/dev/null'
        """
        # file: Rename __close_fd to close_fd and remove the files parameter
        if platform.release() < "5.11.0":
            self.strict_bpf.attach_kprobe(
                event="__close_fd", fn_name="strict___close_fd")
        else:
            self.strict_bpf.attach_kprobe(
                event="close_fd", fn_name="strict_close_fd")
        self.attach_common(self.strict_bpf, 'strict')

    def detach_common(self, b, FUNC):
        b.detach_kprobe(event="put_unused_fd",
                        fn_name=FUNC + "_put_unused_fd")
        if platform.release() > "5.11.0":
            b.detach_kprobe(event="__close_range",
                            fn_name=FUNC + "___close_range")
            b.detach_kprobe(event="close_fd_get_file",
                            fn_name=FUNC + "_close_fd_get_file")
        b.detach_kretprobe(event="get_unused_fd_flags",
                           fn_name=FUNC + "_get_unused_fd_flags")
        b.detach_kretprobe(event="f_dupfd", fn_name=FUNC + "_f_dupfd")

    def detach_loose(self):
        self.bpf.detach_kprobe(event="filp_close",
                               fn_name="loose_filp_close")
        self.detach_common(self.bpf, 'loose')

    def detach_strict(self):
        if platform.release() < "5.11.0":
            self.strict_bpf.detach_kprobe(
                event="__close_fd", fn_name="strict___close_fd")
        else:
            self.strict_bpf.detach_kprobe(
                event="close_fd", fn_name="strict_close_fd")
        self.detach_common(self.strict_bpf, 'strict')

    def stack_trace(self):
        return self.strict_bpf["stack_trace"]

    def pidfd_allocs_hash(self):
        return self.strict_bpf["pidfd_allocs_hash"]

    def pid_count_hash(self):
        return self.bpf["pid_count_hash"]

    def get_user_stack_symbol(self, stack_id, pid):
        bt = []
        for addr in list(self.stack_trace().walk(stack_id)):
            bt.append(self.bpf.sym(
                addr, pid, show_module=True, show_offset=True))
        return bt

    def get_kernel_stack_symbol(self, stack_id):
        bt = []
        for addr in list(self.stack_trace().walk(stack_id)):
            bt.append(self.bpf.ksym(addr, show_offset=True))
        return bt


def get_file_limit():
    flimit = 1024
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        flimit = min(soft, hard)
        if flimit is -1:
            flimit = max(soft, hard)
    except Exception:
        print("Get file resource limit exception.")
    return flimit


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


def parse_args():
    examples = """EXAMPLES:
    ./fdleak
            Trace all process alloc/close file descriptor.
            default internal inspection frequency is 5 seconds,
            default minimim allowable survival time is 30 seconds.
    ./fdleak -p $(pidof allocs)
            Only monitor the allocation and close files of filtered pid
    ./fdleak --csv
            Print fields: Time,Name-PID,FDs
    ./fdleak --lsof
            List the files opened by the monitor process
    ./fdleak -i 60
            Set the internal inspection frequency to 60 seconds
    """
    parser = argparse.ArgumentParser(
        description="Trace FD leak",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
    parser.add_argument("-p", "--pid", default=-1,
            help="trace this PID only")
    parser.add_argument("--csv", action="store_true",
            help="just print fields: comma-separated values")
    parser.add_argument("--lsof", default=False, action="store_true",
            help="list the files opened by the monitor process")
    parser.add_argument("-i", "--interval", default=10, type=int,
            help="interval (in seconds) to scan for outstanding allocations")
    parser.add_argument("--ebpf", action="store_true",
            help=argparse.SUPPRESS)
    args = parser.parse_args()
    return args


class StrictAllocation(object):
    def __init__(self, pid):
        self.thread = set()
        self.pid = pid
        self.name = get_pname(pid) + '-' + str(pid)
        self.fd = []
        self.max_survival_time = 0
        self.stack = {}
        self.stack_cnt = {}

    def update(self, tid, fd, survival_time):
        t = get_tname(self.pid, tid) + "-" + str(tid)
        self.thread.add(t)
        self.fd.append(fd)
        self.max_survival_time = max(survival_time, self.max_survival_time)

    def reset(self):
        self.thread.clear()
        del self.fd[:]
        self.max_survival_time = 0
        self.stack_cnt.setdefault(0)

    def update_stack(self, id, stack):
        if id not in self.stack:
            self.stack[id] = stack
            self.stack_cnt[id] = 1
        self.stack_cnt[id] += 1

    def show_fd(self):
        # -24 is EMFILE, most of the time it means too many open files
        if(self.fd.count(-24) > 0):
            return "\033[1;31m-24\033[0m %d" % max(self.fd)
        else:
            return max(self.fd)


class LooseAllocation(object):
    """
    Loosely record the growth of fd count, If alloc fds keeps growing
    For more information, please refer to `update` function

    arguments:
        init_fds: Initialize the number of fd allocat
        sampling {defalut 3}: Sampling times
    """

    def __init__(self, init_fds, sampling=3):
        self.risk = False
        self.max_fds = init_fds
        self.min_fds = init_fds
        self.min_right_fds = 0
        self.grows = 0
        self.last_min_fds = 0
        self.max_grows = 2
        self.sampling = sampling
        self.flimit = get_file_limit()

    def extend_loose(self):
        """
        Leak is not checked in strict mode, increase the loose condition
        """
        self.risk = False
        self.max_grows = self.grows + 1
        self.sampling = self.sampling * 2

    def update(self, fds):
        """
        growth:
            The observation point on the right side of
            the lowest point continues to exceed the sampling
            and higher than the lowest point of the last increase,
            it is considered as a 'grow'.
        risk flag:
            If grows number more than 'max_grows' or max_fds > 80% file limit.
            The risk flag will be set.
        """
        self.max_fds = max(fds, self.max_fds)
        if self.min_fds < fds:
            self.min_right_fds += 1
            if self.min_right_fds >= self.sampling:
                if self.min_fds > self.last_min_fds:
                    self.grows += 1
                    self.sampling = 2 * self.sampling
                    self.last_min_fds = self.min_fds
                    self.min_fds = self.max_fds
        else:
            self.min_fds = fds
            self.min_right_fds = 0

        if self.flimit != -1 and (self.max_fds > 0.8 * self.flimit):
            self.risk = True
        if self.grows >= self.max_grows:
            self.risk = True

    def check_risk(self):
        return self.risk is True


class FdleakStrict(object):
    def __init__(self, probe, lsof=False):
        self.lsof = lsof
        self.cycles = 0
        self.target_leak = {}
        self.process_alloc_dic = {}
        self.probe = probe
        self.min_allow = 0
        self.flimit = get_file_limit()

    def update_target(self, target_list, min_allow):
        self.min_allow = min_allow
        self.target_leak = dict.fromkeys(target_list, 0)
        self.cycles = 3
        self.process_alloc_dic = {}
        self.probe.load_strict(target_list)
        self.probe.attach_strict()

    def dump_check_result(self):
        for k, v in self.target_leak.items():
            t = datetime.now().strftime("%H:%M:%S")
            if v is 1:
                res = "Found long-term survivors"
            else:
                res = "Not found leak"
            print("[%s] Dump strict check result pid:%d %s" % (t, k, res))

    def list_open_file(self, pid):
        try:
            f = os.popen('ls -al /proc/%d/fd' % pid)
        except Exception:
            return "Unknow"
        return f.read()

    def find_overtime_process(self):
        pidfd_allocs_hash = sorted(self.probe.pidfd_allocs_hash().items(),
                                    key=lambda a: a[1].timestamp)
        overtime_cnt = 0
        time = BPF.monotonic_time() / 1000000000
        for k, alloc_info in pidfd_allocs_hash:
            if((time - alloc_info.timestamp) < self.min_allow):
                break
            pid = alloc_info.pid
            if get_pname(pid) is "Unknow":
                if pid in self.process_alloc_dic:
                    self.process_alloc_dic.pop(pid)
                continue
            if pid not in self.process_alloc_dic:
                self.process_alloc_dic[pid] = StrictAllocation(pid)
            stack_id = alloc_info.user_stack
            if stack_id > 0:
                stack = ["- User Stack"]
                if stack_id not in self.process_alloc_dic[pid].stack_cnt:
                    stack.extend(
                        self.probe.get_user_stack_symbol(stack_id, pid))
            else:
                stack_id = alloc_info.kernel_stack
                stack = ["- Kernel Stack"]
                if stack_id not in self.process_alloc_dic[pid].stack_cnt:
                    stack.extend(self.probe.get_kernel_stack_symbol(stack_id))
            self.process_alloc_dic[pid].update_stack(stack_id, stack)
            self.process_alloc_dic[pid].update(alloc_info.tid, alloc_info.fd, (
                1 + ((int)(time - alloc_info.timestamp))))
            overtime_cnt += 1
        return overtime_cnt

    def print_outstanding_combined(self):
        if self.find_overtime_process() > 0:
            time = '[' + datetime.now().strftime("%H:%M:%S") + ']'
            print("%10s %-20s %-9s %-15s %-8s %-7s %s" %
                  (time, "NAME-PID",
                   "LIMIT",
                   "MAX_SURVIVAL(s)",
                   "MAX_FD",
                   "THREADs",
                   "NAME-TID list"))
            for p, alloc in self.process_alloc_dic.items():
                if p in self.target_leak:
                    self.target_leak[p] = 1
                if alloc.max_survival_time > 0:
                    print(("%10s %-20s %-9s %-15s %-8s %-7s %s\n%10s %s" % (
                        "",
                        alloc.name, self.flimit,
                        alloc.max_survival_time, alloc.show_fd(),
                        len(alloc.thread),
                        " / ".join(str(t) for t in alloc.thread),
                        "", "BackTrace:"
                    )))
                    for id, stack in alloc.stack.items():
                        print("%10s - Stack ID:%d Hits:%d" %
                              ("", id, alloc.stack_cnt[id]))
                        print("%10s %s" % ("", b"\n\t "
                                           .join(stack).decode("ascii")))
                    if self.lsof:
                        print(self.list_open_file(p))
                    alloc.reset()

    def do_strict_check(self, target_list, min_allow=30):
        """
        Do strict fdleak check which will tracks alloc and close of each FD.
        stictly check cycles is '3' times.
        When return `finish` is true, it indicates that the test has been
        completed and the test results is in target_leak dictionary.
        When the return `finish` is false, it's going.

        arguments:
            target_list : list of programs(PID) that need to be tracked
                          it is the keys of target_leak dictionary,
                          the values is the result of detection
                          0 means not found long-term survivors
                          1 meas  found long-term survivors
            min_allow   : the minimum allowable survival time(second)

        return 2 value:
            {finish},{dictionary of target_list:result}
        """
        if self.cycles == 0:
            self.update_target(target_list, min_allow)
            return False, {}
        else:
            self.cycles -= 1
            if self.cycles is 0:
                self.probe.detach_strict()
                return True, self.target_leak
            else:
                self.print_outstanding_combined()
                return False, {}


class Fdleak(object):
    def __init__(self, args):
        self.args = args
        self.probe = Probe(self.args.pid, self.args.ebpf)
        self.loose_check_dic = {}
        self.strict = FdleakStrict(self.probe, self.args.lsof)
        """
        the overhead of strict mode is large,minimum survival
        time is 30 seconds.
        """
        self.survival = 30

    def loose_check(self, pid, fd_cnt):
        """
        Loose check the fd numbers opened by the pid is keeps growing,
        if fdleak risk flag is set, the strict check needs to be activated
        at this time to further determine the risk of leakage.
        """
        if pid not in self.loose_check_dic:
            self.loose_check_dic[pid] = LooseAllocation(fd_cnt)
        else:
            self.loose_check_dic[pid].update(fd_cnt)
        return self.loose_check_dic[pid].check_risk()

    def extend_loose(self, target):
        for pid, leak in target.items():
            if leak is 0:
                self.loose_check_dic[pid].extend_loose()

    def loose_check_handler(self):
        sorted_count_of_pid = self.probe.pid_count_hash().items()
        strict_list = []
        for pid, fd_cnt in sorted_count_of_pid:
            pname = get_pname(pid.value)

            if fd_cnt.value is 0 or pname is "Unknow":
                continue
            if self.args.csv:
                print("%s,%s,%s" % (datetime.now().strftime(
                    "%H:%M:%S"), (pname + '_' + str(pid.value)), fd_cnt.value))
            if self.loose_check(pid.value, fd_cnt.value):
                strict_list.append(pid.value)
        if len(strict_list) > 0:
            # Same process attaches to same symbol is not supported by BPF
            self.probe.detach_loose()
            while True:
                try:
                    finish, target_leak = self.strict.do_strict_check(
                        strict_list, self.survival)
                    sleep(self.survival)
                    if finish:
                        self.extend_loose(target_leak)
                        break
                except KeyboardInterrupt:
                    print("\nBye~Bye...")
                    exit()
            self.probe.attach_loose()

    def run(self):
        self.probe.load_loose()
        self.probe.attach_loose()

        print("Trace and display fd alloc/close to detect "
              "FD leaks process,Hit Ctrl-C to exit.")

        if self.args.csv:
            print("Time,Name-PID,FDs")
        while True:
            try:
                sleep(self.args.interval)
            except KeyboardInterrupt:
                print("\nBye~Bye...")
                exit()
            self.loose_check_handler()


if __name__ == "__main__":
    args = parse_args()
    try:
        fdleak = Fdleak(args)
        fdleak.run()
    except Exception:
        if sys.exc_info()[0] is not SystemExit:
            traceback.print_exc()
            print(sys.exc_info()[1])

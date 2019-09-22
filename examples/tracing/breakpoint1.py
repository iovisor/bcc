#!/usr/bin/python

# This is another example of a hardware breakpoint on a kernel address.
# This prints the stack trace once the address is accessed by any process.
# run in project examples directory with:
# sudo ./breakpoint1.py"
# <0xaddress> <pid> <breakpoint_type>
# HW_BREAKPOINT_W = 2
# HW_BREAKPOINT_RW = 3

# You may need to clear the old tracepipe inputs before running the script by : 
# echo > /sys/kernel/debug/tracing/trace 

# 10-Jul-2019   Aanandita Dhawan   Created this.

from __future__ import print_function
from bcc import BPF, PerfType, PerfSWConfig
from sys import stderr
from time import sleep
import signal
import os
import errno

def stack_id_err(stack_id):
    # -EFAULT in get_stackid normally means the stack-trace is not available,
    # Such as getting kernel stack trace in userspace code
    return (stack_id < 0) and (stack_id != -errno.EFAULT)

bpf_text = """
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

struct stack_key_t {
  int pid;
  char name[16];
  int user_stack_id;
  int kernel_stack_id;
};

BPF_STACK_TRACE(stack_traces, 16384);
BPF_HASH(counts, struct stack_key_t, uint64_t);

int func(struct pt_regs *ctx) {
  struct stack_key_t key = {};
  key.pid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(&key.name, sizeof(key.name));
  key.kernel_stack_id = stack_traces.get_stackid(ctx, 0);
  key.user_stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

  u64 zero = 0, *val;
  val = counts.lookup_or_init(&key, &zero);
  (*val)++;

  bpf_trace_printk("Hello World, Here I accessed the address!\\n");

  return 0;

}

"""
b = BPF(text=bpf_text)
symbol_addr = input()
pid = input()
bp_type = input()

b.attach_breakpoint(symbol_addr, pid, "func", bp_type)

def signal_ignore(signal, frame):
    print()

try:
    sleep(100)
except KeyboardInterrupt:
    signal.signal(signal.SIGINT, signal_ignore)

counts = b.get_table("counts")
stack_traces = b.get_table("stack_traces")

for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):

    user_tmp = [] if k.user_stack_id < 0 else \
        stack_traces.walk(k.user_stack_id)
    kernel_tmp = [] if k.kernel_stack_id < 0 else \
        stack_traces.walk(k.kernel_stack_id)

    # fix the stacks
    kernel_stack = []
    if k.kernel_stack_id >= 0:
        for addr in kernel_tmp:
            kernel_stack.append(addr)
    user_stack = []
    if k.user_stack_id >= 0:
        for addr in user_tmp:
            user_stack.append(addr)

    user_stack = list(user_stack)
    kernel_stack = list(kernel_stack)
    
    if stack_id_err(k.kernel_stack_id):
        print("    [Missed Kernel Stack]")
    else:
        print(" Kernel Stack : \n")
        for addr in kernel_stack:
            print("    %s" % b.ksym(addr))

    if stack_id_err(k.user_stack_id):
        print("    [Missed User Stack]")
            
    else:
        print("\n User Stack : \n")
        for addr in user_stack:
            print("    %s" % b.sym(addr, k.pid).decode('utf-8', 'replace'))
    print("    %-16s %s (%d)" % ("-", k.name.decode('utf-8', 'replace'), k.pid))
    print("        %d\n" % v.value)


#!/usr/bin/python
#
# An example usage of stack_build_id
# Most of the code here is borrowed from tools/profile.py
#
# Steps for using this code
# 1) Start ping program in one terminal eg invocation: ping google.com -i0.001
# 2) Change the path of libc specified in b.add_module() below
# 3) Invoke the script as 'python stack_buildid_example.py'
# 4) o/p of the tool is as shown below
#  python example/tracing/stack_buildid_example.py
#    sendto
#    -                ping (5232)
#        2
#
# REQUIRES: Linux 4.17+ (BPF_BUILD_ID support)
# Licensed under the Apache License, Version 2.0 (the "License")
# 03-Jan-2019  Vijay Nag

from __future__ import print_function
from bcc import BPF, PerfType, PerfSWConfig
from sys import stderr
from time import sleep
import argparse
import signal
import os
import subprocess
import errno
import multiprocessing
import ctypes as ct

def Get_libc_path():
  # A small helper function that returns full path
  # of libc in the system
  cmd = 'cat /proc/self/maps | grep libc | awk \'{print $6}\' | uniq'
  output = subprocess.check_output(cmd, shell=True)
  if not isinstance(output, str):
    output = output.decode()
  return output.split('\n')[0]

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>

struct key_t {
    u32 pid;
    int user_stack_id;
    char name[TASK_COMM_LEN];
};
BPF_HASH(counts, struct key_t);
BPF_STACK_TRACE_BUILDID(stack_traces, 128);

int do_perf_event(struct bpf_perf_event_data *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // create map key
    struct key_t key = {.pid = pid};
    bpf_get_current_comm(&key.name, sizeof(key.name));

    key.user_stack_id = stack_traces.get_stackid(&ctx->regs, BPF_F_USER_STACK);

    if (key.user_stack_id >= 0) {
      counts.increment(key);
    }
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_perf_event(ev_type=PerfType.SOFTWARE,
    ev_config=PerfSWConfig.CPU_CLOCK, fn_name="do_perf_event",
    sample_period=0, sample_freq=49, cpu=0)

# Add the list of libraries/executables to the build sym cache for sym resolution
# Change the libc path if it is different on a different machine.
# libc.so and ping are added here so that any symbols pertaining to
# libc or ping are resolved. More executables/libraries can be added here.
b.add_module(Get_libc_path())
b.add_module("/usr/sbin/sshd")
b.add_module("/bin/ping")
counts = b.get_table("counts")
stack_traces = b.get_table("stack_traces")
duration = 2

def signal_handler(signal, frame):
  print()

try:
    sleep(duration)
except KeyboardInterrupt:
    # as cleanup can take some time, trap Ctrl-C:
    signal.signal(signal.SIGINT, signal.SIG_IGN)

user_stack=[]
for k,v in sorted(counts.items(), key=lambda counts: counts[1].value):
  user_stack = [] if k.user_stack_id < 0 else \
      stack_traces.walk(k.user_stack_id)

  user_stack=list(user_stack)
  for addr in user_stack:
    print("    %s" % b.sym(addr, k.pid).decode('utf-8', 'replace'))
  print("    %-16s %s (%d)" % ("-", k.name.decode('utf-8', 'replace'), k.pid))
  print("        %d\n" % v.value)


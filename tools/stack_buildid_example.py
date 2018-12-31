
# An example usage of stack_build_id
# Most of the code here is borrowed from tools/profile.py

from __future__ import print_function
from bcc import BPF, PerfType, PerfSWConfig
from sys import stderr
from time import sleep
import argparse
import signal
import os
import errno
import multiprocessing
import ctypes as ct

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>

#define STACK_STORAGE_SIZE 64 //should be less than 128

struct key_t {
    u32 pid;
    int user_stack_id;
    char name[TASK_COMM_LEN];
};
BPF_HASH(counts, struct key_t);
BPF_STACK_TRACE_BUILDID(stack_traces, STACK_STORAGE_SIZE);

// This code gets a bit complex. Probably not suitable for casual hacking.
int do_perf_event(struct bpf_perf_event_data *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!(1))
        return 0;

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

#Add the required builds here
b.add_module("/lib/x86_64-linux-gnu/libc.so.6")
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
    signal.signal(signal.SIGINT, signal_ignore)

user_stack=[]
for k,v in sorted(counts.items(), key=lambda counts: counts[1].value):
  user_stack = [] if k.user_stack_id < 0 else \
      stack_traces.walk(k.user_stack_id)

  user_stack=list(user_stack)
  for addr in user_stack:
    print("    %s" % b.sym(addr, k.pid).decode('utf-8', 'replace'))
  print("    %-16s %s (%d)" % ("-", k.name.decode('utf-8', 'replace'), k.pid))
  print("        %d\n" % v.value)


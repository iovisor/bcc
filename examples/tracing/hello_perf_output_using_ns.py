#!/usr/bin/python
# Carlos Neira <cneirabustos@gmail.com>
# This is a Hello World example that uses BPF_PERF_OUTPUT.
# in this example bpf_get_ns_current_pid_tgid(), this helper
# works inside pid namespaces.
# bpf_get_current_pid_tgid() only returns the host pid outside any
# namespace and this will not work when the script is run inside a pid namespace.

from bcc import BPF
from bcc.utils import printb
import sys, os
from stat import *

# define BPF program
prog = """
#include <linux/sched.h>

// define output data structure in C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

int hello(struct pt_regs *ctx) {
    struct data_t data = {};
    struct bpf_pidns_info ns = {};

    if(bpf_get_ns_current_pid_tgid(DEV, INO, &ns, sizeof(struct bpf_pidns_info)))
	return 0;
    data.pid = ns.pid;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

devinfo = os.stat("/proc/self/ns/pid")
for r in (("DEV", str(devinfo.st_dev)), ("INO", str(devinfo.st_ino))):
    prog = prog.replace(*r)

# load BPF program
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# process event
start = 0


def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
    if start == 0:
        start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    printb(
        b"%-18.9f %-16s %-6d %s"
        % (time_s, event.comm, event.pid, b"Hello, perf_output!")
    )


# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

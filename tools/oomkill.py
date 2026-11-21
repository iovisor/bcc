#!/usr/bin/env python
#
# oomkill   Trace oom_kill_process(). For Linux, uses BCC, eBPF.
#
# This traces the kernel out-of-memory killer, and prints basic details,
# including the system load averages. This can provide more context on the
# system state at the time of OOM: was it getting busier or steady, based
# on the load averages? This tool may also be useful to customize for
# investigations; for example, by adding other task_struct details at the time
# of OOM.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 09-Feb-2016   Brendan Gregg   Created this.

import argparse
from bcc import BPF
from time import strftime

# arguments
examples = """examples:
    ./oomkill           # trace OOM kills
    ./oomkill -s        # trace OOM kills and print victim user stack trace
"""
parser = argparse.ArgumentParser(
    description="Trace the kernel out-of-memory killer",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument(
    "-s", "--stack", action="store_true",
    help="print victim process user-space stack trace")
args = parser.parse_args()

# linux stats
loadavg = "/proc/loadavg"

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/oom.h>

#define MAX_STACK_DEPTH 127

struct data_t {
    u32 fpid;
    u32 tpid;
    u64 pages;
    u32 stack_id;
    char fcomm[TASK_COMM_LEN];
    char tcomm[TASK_COMM_LEN];
};

#ifdef CAPTURE_STACK
struct victim_data_t {
    u32 fpid;
    u32 tpid;
    u64 pages;
    u32 stack_id;
    char fcomm[TASK_COMM_LEN];
    char tcomm[TASK_COMM_LEN];
    int stack_len;
    u64 user_stack[MAX_STACK_DEPTH];
};
BPF_PERCPU_ARRAY(data_tmp, struct victim_data_t, 1);
#endif

BPF_PERF_OUTPUT(events);
BPF_STACK_TRACE(stack_traces, 1024);

#ifdef CAPTURE_STACK
KFUNC_PROBE(oom_kill_process, struct oom_control *oc, const char *message)
#else
void kprobe__oom_kill_process(struct pt_regs *ctx, struct oom_control *oc, const char *message)
#endif
{
    struct task_struct *p = oc->chosen;
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    data.fpid = pid;
    data.tpid = p->tgid;
    data.pages = oc->totalpages;
    bpf_get_current_comm(&data.fcomm, sizeof(data.fcomm));
    bpf_probe_read_kernel(&data.tcomm, sizeof(data.tcomm), p->comm);

#ifdef CAPTURE_STACK
    int zero = 0;
    struct victim_data_t *vdata = data_tmp.lookup(&zero);
    if (!vdata)
        return 0;

    vdata->fpid = data.fpid;
    vdata->tpid = data.tpid;
    vdata->pages = data.pages;
    vdata->stack_id = 0;
    __builtin_memcpy(vdata->fcomm, data.fcomm, sizeof(data.fcomm));
    __builtin_memcpy(vdata->tcomm, data.tcomm, sizeof(data.tcomm));
    vdata->stack_len = -1;
    if (p) {
        vdata->stack_len = bpf_get_task_stack(p, vdata->user_stack,
                                              sizeof(vdata->user_stack),
                                              BPF_F_USER_STACK);
    }
    events.perf_submit(ctx, vdata, sizeof(*vdata));
    return 0;
#else
    // Capture the user stack trace
    data.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    events.perf_submit(ctx, &data, sizeof(data));
#endif
}
"""

if args.stack:
    bpf_text = "#define CAPTURE_STACK\n" + bpf_text

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    with open(loadavg) as stats:
        avgline = stats.read().rstrip()
    print(("%s Triggered by PID %d (\"%s\"), OOM kill of PID %d (\"%s\")"
        ", %d pages, loadavg: %s") % (strftime("%H:%M:%S"), event.fpid,
        event.fcomm.decode('utf-8', 'replace'), event.tpid,
        event.tcomm.decode('utf-8', 'replace'), event.pages, avgline))

    if args.stack:
        if event.stack_len > 0:
            print("  Victim stack trace:")
            num_frames = event.stack_len // 8
            for i in range(num_frames):
                addr = event.user_stack[i]
                sym = b.sym(addr, event.tpid, show_module=True, show_offset=True)
                print("    %s" % sym.decode('utf-8', 'replace'))
        else:
            print("  Failed to capture victim stack trace (%d)" % event.stack_len)
        return

    # Print the stack trace if stack_id is non-negative
    if event.stack_id >= 0:
        print("  Stack trace:")
        stack_traces = b["stack_traces"]
        for addr in stack_traces.walk(event.stack_id):
            print(f"    {b.sym(addr, event.tpid)}")
    else:
        print("  Failed to capture stack trace")

# initialize BPF
b = BPF(text=bpf_text)
print("Tracing OOM kills... Ctrl-C to stop.")
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

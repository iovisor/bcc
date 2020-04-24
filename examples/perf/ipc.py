#!/usr/bin/python
# IPC - Instructions Per Cycles using Perf Events and
# uprobes
# 24-Apr-2020	Saleem Ahmad	Created this.

from __future__ import print_function
from bcc import BPF, USDT, Perf
from bcc.utils import printb
from time import sleep
import sys
from optparse import OptionParser

# load BPF program
code="""
#include <uapi/linux/ptrace.h>

struct perf_delta {
    u64 clk_delta;
    u64 inst_delta;
    u64 time_delta;
};

// Perf Arrays to read counter values for open
// perf events.
BPF_PERF_ARRAY(clk, 16);
BPF_PERF_ARRAY(inst, 16);

// Perf Output
BPF_PERF_OUTPUT(output);

// Per Cpu Data to store start values
BPF_PERCPU_ARRAY(data, u64);

void trace_start(struct pt_regs *ctx) {
    u32 clk_k = 0;
    u32 inst_k = 1;
    u32 time = 2;

    int cpu = bpf_get_smp_processor_id();
    u64 clk_start = clk.perf_read(cpu);
    u64 inst_start = inst.perf_read(cpu);
    u64 time_start = bpf_ktime_get_ns();
    
    u64* kptr = NULL;
    kptr = data.lookup(&clk_k);
    if (kptr) {
        data.update(&clk_k, &clk_start);
    } else {
        data.insert(&clk_k, &clk_start);
    }

    kptr = data.lookup(&inst_k);
    if (kptr) {
        data.update(&inst_k, &inst_start);
    } else {
        data.insert(&inst_k, &inst_start);
    }

    kptr = data.lookup(&time);
    if (kptr) {
        data.update(&time, &time_start);
    } else {
        data.insert(&time, &time_start);
    }
}

void trace_end(struct pt_regs* ctx) {
    u32 clk_k = 0;
    u32 inst_k = 1;
    u32 time = 2;

    int cpu = bpf_get_smp_processor_id();
    u64 clk_end = clk.perf_read(cpu);
    u64 inst_end = inst.perf_read(cpu);
    u64 time_end = bpf_ktime_get_ns();
    
    struct perf_delta perf_data = {} ;
    bool submit = true;
    u64* kptr = NULL;
    kptr = data.lookup(&clk_k);
    if (kptr) {
        perf_data.clk_delta = clk_end - *kptr;
    }
    
    kptr = data.lookup(&inst_k);
    if (kptr) {
        perf_data.inst_delta = inst_end - *kptr;
    } else {
        submit = false;
    }

    kptr = data.lookup(&time);
    if (kptr) {
        perf_data.time_delta = time_end - *kptr;
    } else {
        submit = false;
    }

    if (submit) {
        output.perf_submit(ctx, &perf_data, sizeof(struct perf_delta));
    }
}
"""

usage='Usage: ipc.py [options]\nexample ./ipc.py -l c -s strlen'
parser = OptionParser(usage)
parser.add_option('-l', '--lib', dest='lib_name', help='lib name containing symbol to trace, e.g. c for libc', type=str)
parser.add_option('-s', '--sym', dest='sym', help='symbol to trace', type=str)

(options, args) = parser.parse_args()
if (not options.lib_name or not options.sym):
    parser.print_help()
    exit()

b = BPF(text=code)

# Attach Probes at start and end of the trace function
# NOTE: When attaching to a function for tracing, during runtime relocation
# stage by linker, function will be called once to return a different function
# address, which will be called by the process. e.g. in case of strlen
# after relocation stage, __strlen_sse2 is called instread of strlen.
# NOTE: There will be a context switch from userspace to kernel space,
# on caputring counters on USDT probes, so actual IPC might be slightly different.
# This example is to give a reference on how to use perf events with tracing.
b.attach_uprobe(name=options.lib_name, sym=options.sym, fn_name="trace_start")
b.attach_uretprobe(name=options.lib_name, sym=options.sym, fn_name="trace_end")

def print_data(cpu, data, size):
    e = b["output"].event(data)
    try:
        print("%-8d %-8d %-8.2f %-8s %d" % (e.clk_delta, e.inst_delta, 
            1.0* e.inst_delta/e.clk_delta, str(round(e.time_delta * 1e-3, 2)) + ' us', cpu))
    except Exception as e:
        print(e)

print("Counters Data")
print("%-8s %-8s %-8s %-8s %s" % ('CLK', 'INST', 'IPC', 'TIME', 'CPU'))

b["output"].open_perf_buffer(print_data)

# Perf Event for Unhalted Cycles, The hex value is
# combination of event, umask and cmask. Read Intel
# Doc to find the event and cmask. Or use 
# perf list --details to get event, umask and cmask

PERF_EVENT_RAW = 4
# Unhalted Clock Cycles
b["clk"].open_perf_event(PERF_EVENT_RAW, 0x0000003C)
# Instruction Retired
b["inst"].open_perf_event(PERF_EVENT_RAW, 0x000000C0)

while True:
	try:
	    b.perf_buffer_poll()
	except KeyboardInterrupt:
            exit()

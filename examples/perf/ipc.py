#!/usr/bin/python
# IPC - Instructions Per Cycles using Perf Events and
# uprobes
# 24-Apr-2020	Saleem Ahmad	Created this.

from bcc import BPF, utils
from optparse import OptionParser

# load BPF program
code="""
#include <uapi/linux/ptrace.h>

struct perf_delta {
    u64 clk_delta;
    u64 inst_delta;
    u64 time_delta;
};

/*
Perf Arrays to read counter values for open
perf events.
*/
BPF_PERF_ARRAY(clk, MAX_CPUS);
BPF_PERF_ARRAY(inst, MAX_CPUS);

// Perf Output
BPF_PERF_OUTPUT(output);

// Per Cpu Data to store start values
BPF_PERCPU_ARRAY(data, u64);

#define CLOCK_ID 0
#define INSTRUCTION_ID 1
#define TIME_ID 2

void trace_start(struct pt_regs *ctx) {
    u32 clk_k = CLOCK_ID;
    u32 inst_k = INSTRUCTION_ID;
    u32 time = TIME_ID;

    int cpu = bpf_get_smp_processor_id();
    /*
    perf_read may return negative values for errors.
    If cpu id is greater than BPF_PERF_ARRAY size,
    counters values will be very large negative number.
    NOTE: Use bpf_perf_event_value is recommended over
    bpf_perf_event_read or map.perf_read() due to
    issues in ABI. map.perf_read_value() need to be
    implemented in future.
    */
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
    u32 clk_k = CLOCK_ID;
    u32 inst_k = INSTRUCTION_ID;
    u32 time = TIME_ID;

    int cpu = bpf_get_smp_processor_id();
    /*
    perf_read may return negative values for errors.
    If cpu id is greater than BPF_PERF_ARRAY size,
    counters values will be very large negative number.
    NOTE: Use bpf_perf_event_value is recommended over
    bpf_perf_event_read or map.perf_read() due to
    issues in ABI. map.perf_read_value() need to be
    implemented in future.
    */
    u64 clk_end = clk.perf_read(cpu);
    u64 inst_end = inst.perf_read(cpu);
    u64 time_end = bpf_ktime_get_ns();
    
    struct perf_delta perf_data = {} ;
    u64* kptr = NULL;
    kptr = data.lookup(&clk_k);

    // Find elements in map, if not found return
    if (kptr) {
        perf_data.clk_delta = clk_end - *kptr;
    } else {
        return;
    }
    
    kptr = data.lookup(&inst_k);
    if (kptr) {
        perf_data.inst_delta = inst_end - *kptr;
    } else {
        return;
    }

    kptr = data.lookup(&time);
    if (kptr) {
        perf_data.time_delta = time_end - *kptr;
    } else {
        return;
    }

    output.perf_submit(ctx, &perf_data, sizeof(struct perf_delta));
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

num_cpus = len(utils.get_online_cpus())

b = BPF(text=code, cflags=['-DMAX_CPUS=%s' % str(num_cpus)])

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
    print("%-8d %-12d %-8.2f %-8s %d" % (e.clk_delta, e.inst_delta, 
        1.0* e.inst_delta/e.clk_delta, str(round(e.time_delta * 1e-3, 2)) + ' us', cpu))

print("Counters Data")
print("%-8s %-12s %-8s %-8s %s" % ('CLOCK', 'INSTRUCTION', 'IPC', 'TIME', 'CPU'))

b["output"].open_perf_buffer(print_data)

# Perf Event for Unhalted Cycles, The hex value is
# combination of event, umask and cmask. Read Intel
# Doc to find the event and cmask. Or use 
# perf list --details to get event, umask and cmask
# NOTE: Events can be multiplexed by kernel in case the
# number of counters is greater than supported by CPU
# performance monitoring unit, which can result in inaccurate
# results. Counter values need to be normalized for a more
# accurate value.
PERF_TYPE_RAW = 4
# Unhalted Clock Cycles
b["clk"].open_perf_event(PERF_TYPE_RAW, 0x0000003C)
# Instruction Retired
b["inst"].open_perf_event(PERF_TYPE_RAW, 0x000000C0)

while True:
	try:
	    b.perf_buffer_poll()
	except KeyboardInterrupt:
            exit()

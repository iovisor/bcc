#!/usr/bin/python
import argparse
from time import sleep, strftime
from sys import argv
import ctypes as ct
from bcc import BPF, USDT
import inspect
import os

# Parse command line arguments
parser = argparse.ArgumentParser(description="Trace the moving average of the latency of an operation using usdt probes.",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-p", "--pid", type=int, help="The id of the process to trace.")
parser.add_argument("-i", "--interval", type=int, help="The interval in seconds on which to report the latency distribution.")
parser.add_argument("-c", "--count", type=int, default=16, help="The maximum number of samples over which to calculate the moving average.")
parser.add_argument("-f", "--filterstr", type=str, default="", help="The prefix filter for the operation input. If specified, only operations for which the input string starts with the filterstr are traced.")
parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="If true, will output generated bpf program and verbose logging information.")
parser.add_argument("-s", "--sdt", dest="sdt", action="store_true", help="If true, will use the probes, created by systemtap's dtrace.")

parser.set_defaults(verbose=False)
args = parser.parse_args()
this_pid = int(args.pid)
this_interval = int(args.interval)
this_maxsamplesize = int(args.count)
this_filter = str(args.filterstr)

if this_interval < 1:
    print("Invalid value for interval, using 1.")
    this_interval = 1

if this_maxsamplesize < 1:
    print("Invalid value for this_maxsamplesize, using 1.")
    this_maxsamplesize = 1

debugLevel=0
if args.verbose:
    debugLevel=4

# BPF program
bpf_text_shared = "%s/bpf_text_shared.c" % os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
bpf_text = open(bpf_text_shared, 'r').read()
bpf_text += """

const u32 max_sample_size = MAX_SAMPLE_SIZE;

struct hash_key_t
{
    char input[64]; // The operation id is used as key
};

struct hash_leaf_t
{
    u32 sample_size;    // Number of operation samples taken
    u64 total;          // Cumulative duration of the operations
    u64 average;        // Moving average duration of the operations
};

/**
 * @brief Contains the averages for the operation latencies by operation input.
 */
BPF_HASH(lat_hash, struct hash_key_t, struct hash_leaf_t, 512);

/**
 * @brief Reads the operation response arguments, calculates the latency, and stores it in the histogram.
 * @param ctx The BPF context.
 */
int trace_operation_end(struct pt_regs* ctx)
{
    u64 operation_id;
    bpf_usdt_readarg(1, ctx, &operation_id);

    struct start_data_t* start_data = start_hash.lookup(&operation_id);
    if (0 == start_data) {
        return 0;
    }

    u64 duration = bpf_ktime_get_ns() - start_data->start;
    struct hash_key_t hash_key = {};
    __builtin_memcpy(&hash_key.input, start_data->input, sizeof(hash_key.input));
    start_hash.delete(&operation_id);

    struct hash_leaf_t zero = {};
    struct hash_leaf_t* hash_leaf = lat_hash.lookup_or_try_init(&hash_key, &zero);
    if (0 == hash_leaf) {
        return 0;
    }

    if (hash_leaf->sample_size < max_sample_size) {
        ++hash_leaf->sample_size;
    } else {
        hash_leaf->total -= hash_leaf->average;
    }

    hash_leaf->total += duration;
    hash_leaf->average = hash_leaf->total / hash_leaf->sample_size;

    return 0;
}
"""

bpf_text = bpf_text.replace("MAX_SAMPLE_SIZE", str(this_maxsamplesize))
bpf_text = bpf_text.replace("FILTER_STRING", this_filter)
if this_filter:
    bpf_text = bpf_text.replace("FILTER_STATEMENT", "if (!filter(start_data.input)) { return 0; }")
else:
    bpf_text = bpf_text.replace("FILTER_STATEMENT", "")

# Create USDT context
print("lat_avg.py - Attaching probes to pid: %d; filter: %s" % (this_pid, this_filter))
usdt_ctx = USDT(pid=this_pid)

if args.sdt:
    usdt_ctx.enable_probe(probe="usdt_sample_lib1_sdt:operation_start_sdt", fn_name="trace_operation_start")
    usdt_ctx.enable_probe(probe="usdt_sample_lib1_sdt:operation_end_sdt", fn_name="trace_operation_end")
else:
    usdt_ctx.enable_probe(probe="usdt_sample_lib1:operation_start", fn_name="trace_operation_start")
    usdt_ctx.enable_probe(probe="usdt_sample_lib1:operation_end", fn_name="trace_operation_end")

# Create BPF context, load BPF program
bpf_ctx = BPF(text=bpf_text, usdt_contexts=[usdt_ctx], debug=debugLevel)

print("Tracing... Hit Ctrl-C to end.")

lat_hash = bpf_ctx.get_table("lat_hash")
print("%-12s %-64s %8s %16s" % ("time", "input", "sample_size", "latency (us)"))
while (1):
    try:
        sleep(this_interval)
    except KeyboardInterrupt:
        exit()

    for k, v in lat_hash.items():
        print("%-12s %-64s %8d %16d" % (strftime("%H:%M:%S"), k.input, v.sample_size, v.average / 1000))

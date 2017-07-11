import argparse
from time import sleep, strftime
from sys import argv
import ctypes as ct
from bcc import BPF, USDT
import inspect
import os

# Parse command line arguments
parser = argparse.ArgumentParser(description="Trace the latency distribution of an operation using usdt probes.",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-p", "--pid", type=int, help="The id of the process to trace.")
parser.add_argument("-i", "--interval", type=int, help="The interval in seconds on which to report the latency distribution.")
parser.add_argument("-f", "--filterstr", type=str, default="", help="The prefix filter for the operation input. If specified, only operations for which the input string starts with the filterstr are traced.")
parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="If true, will output verbose logging information.")
parser.set_defaults(verbose=False)
args = parser.parse_args()
this_pid = int(args.pid)
this_interval = int(args.interval)
this_filter = str(args.filterstr)

if this_interval < 1:
    print("Invalid value for interval, using 1.")
    this_interval = 1

debugLevel=0
if args.verbose:
    debugLevel=4

# BPF program
bpf_text_shared = "%s/bpf_text_shared.c" % os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
bpf_text = open(bpf_text_shared, 'r').read()
bpf_text += """

/**
 * @brief The key to use for the latency histogram.
 */
struct dist_key_t
{
    char input[64];   ///< The input string of the request.
    u64 slot;         ///< The histogram slot.
};

/**
 * @brief Contains the histogram for the operation latencies.
 */
BPF_HISTOGRAM(dist, struct dist_key_t);

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
    struct dist_key_t dist_key = {};
    __builtin_memcpy(&dist_key.input, start_data->input, sizeof(dist_key.input));
    dist_key.slot = bpf_log2l(duration / 1000);
    start_hash.delete(&operation_id);

    dist.increment(dist_key);
    return 0;
}
"""

bpf_text = bpf_text.replace("FILTER_STRING", this_filter)
if this_filter:
    bpf_text = bpf_text.replace("FILTER", "if (!filter(start_data.input)) { return 0; }")
else:
    bpf_text = bpf_text.replace("FILTER", "")

# Create USDT context
print("Attaching probes to pid %d" % this_pid)
usdt_ctx = USDT(pid=this_pid)
usdt_ctx.enable_probe(probe="operation_start", fn_name="trace_operation_start")
usdt_ctx.enable_probe(probe="operation_end", fn_name="trace_operation_end")

# Create BPF context, load BPF program
bpf_ctx = BPF(text=bpf_text, usdt_contexts=[usdt_ctx], debug=debugLevel)

start = 0
dist = bpf_ctx.get_table("dist")
while (1):
    try:
        sleep(this_interval)
    except KeyboardInterrupt:
        exit()

    print("[%s]" % strftime("%H:%M:%S"))
    dist.print_log2_hist("latency (us)")

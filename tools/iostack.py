#!/usr/bin/python

from bcc import BPF
from time import sleep
import argparse
import signal
from sys import stderr

# define BPF program
bpf_text = """
#include <linux/blkdev.h>
#include <linux/blk_types.h>

// define output data structure in C
struct data_t {
    char disk_name[DISK_NAME_LEN];
    int kernel_stack_id;
    int user_stack_id;
    u64 tgid_pid;
};

BPF_HASH(counts, struct data_t);
BPF_STACK_TRACE(stack_traces, 16384);

int _generic_make_request(struct pt_regs *ctx, struct bio *bio) {
    struct data_t data = {};

    struct gendisk *bio_disk = bio->bi_disk;
    bpf_probe_read_kernel(&data.disk_name, sizeof(data.disk_name),
                       bio_disk->disk_name);
#ifdef KERNEL_STACK
    data.kernel_stack_id = stack_traces.get_stackid(ctx, 0);
#endif
#ifdef USER_STACK
    data.user_stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
    data.tgid_pid = bpf_get_current_pid_tgid();
#endif

    counts.increment(data, bio->bi_iter.bi_size);

    return 0;
}
"""

examples = """examples:
    ./stackcount submit_bio         # count kernel stack traces for submit_bio
    ./stackcount -d ip_output       # include a user/kernel stack delimiter
    ./stackcount -s ip_output       # show symbol offsets
    ./stackcount -sv ip_output      # show offsets and raw addresses (verbose)
    ./stackcount 'tcp_send*'        # count stacks for funcs matching tcp_send*
    ./stackcount -r '^tcp_send.*'   # same as above, using regular expressions
    ./stackcount -Ti 5 ip_output    # output every 5 seconds, with timestamps
    ./stackcount -p 185 ip_output   # count ip_output stacks for PID 185 only
    ./stackcount -c 1 put_prev_entity   # count put_prev_entity stacks for CPU 1 only
    ./stackcount -p 185 c:malloc    # count stacks for malloc in PID 185
    ./stackcount t:sched:sched_fork # count stacks for sched_fork tracepoint
    ./stackcount -p 185 u:node:*    # count stacks for all USDT probes in node
    ./stackcount -K t:sched:sched_switch   # kernel stacks only
    ./stackcount -U t:sched:sched_switch   # user stacks only
        """
parser = argparse.ArgumentParser(
    description="Count events and their stack traces",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", type=int,
                    help="trace this PID only")
parser.add_argument("-i", "--interval",
                    help="summary interval, seconds")
parser.add_argument("-D", "--duration",
                    help="total duration of trace, seconds")
parser.add_argument("-K", "--kernel-stack",
                    action="store_true", help="kernel stack only")
parser.add_argument("-U", "--user-stack",
                    action="store_true", help="user stack only")
parser.add_argument("-f", "--folded", action="store_true",
                    help="output folded format")
parser.add_argument("--debug", action="store_true",
                    help="print BPF program before starting (for debugging purposes)")

args = parser.parse_args()

folded = True

if args.user_stack:
    bpf_text = "#define USER_STACK\n" + bpf_text
if args.kernel_stack:
    bpf_text = "#define KERNEL_STACK\n" + bpf_text

# load BPF program
b = BPF(text=bpf_text)
b.attach_kprobe(event="generic_make_request", fn_name="_generic_make_request")
matched = b.num_open_kprobes()
if matched == 0:
    print("error: 0 functions traced. Exiting.", file=stderr)
    exit(1)

duration = int(args.duration)
# header
if not args.folded:
    print("Tracing total io sizes (bytes) of %s by %s stack", end="")
    if duration < 99999999:
        print(" for %d secs." % duration)
    else:
        print("... Hit Ctrl-C to end.")

# signal handler
def signal_ignore(signal, frame):
    print()

try:
    sleep(duration)
except KeyboardInterrupt:
    # as cleanup can take many seconds, trap Ctrl-C:
    signal.signal(signal.SIGINT, signal_ignore)

counts = b.get_table("counts")
stack_traces = b.get_table("stack_traces")

for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    user_stack = []

    if args.user_stack and k.user_stack_id > 0:
        user_stack = stack_traces.walk(k.user_stack_id)

    kernel_stack = []
    if args.kernel_stack and k.kernel_stack_id > 0:
        kernel_stack = stack_traces.walk(k.kernel_stack_id)

    do_delimiter = user_stack and kernel_stack

    if args.folded:
        # print folded stack output
        user_stack = list(user_stack)
        kernel_stack = list(kernel_stack)
        line = [b.sym(addr, k.tgid).decode('utf-8', 'replace') for addr in
                reversed(user_stack)] + \
               (do_delimiter and ["-"] or []) + \
               [b.ksym(addr).decode('utf-8', 'replace') for addr in
                reversed(kernel_stack)] + \
               [k.disk_name.decode('utf-8', 'replace')]
        print("%s %d" % (";".join(line), v.value))
    else:
        print("disk %s" % k.disk_name.decode('utf-8', 'replace'))
        # print default multi-line stack output.
        for addr in kernel_stack:
            print("    %s" % b.ksym(addr).decode('utf-8', 'replace'))
        if do_delimiter:
            print("    --")
        for addr in user_stack:
            print("    %s" % b.sym(addr, k.tgid_pid).decode('utf-8', 'replace'))

        print("        %d\n" % v.value)

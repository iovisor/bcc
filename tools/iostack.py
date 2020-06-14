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

struct disk_data_t {
    char disk_name[DISK_NAME_LEN];
    int kernel_stack_id;
    int user_stack_id;
    u64 tgid_pid;
    char comm_name[TASK_COMM_LEN];
};

BPF_HASH(counts, struct disk_data_t);
BPF_STACK_TRACE(stack_traces, 16384);

int _generic_make_request(struct pt_regs *ctx, struct bio *bio) {
    struct disk_data_t data = {};
    u32 bi_size = bio->bi_iter.bi_size;
    struct gendisk *bio_disk = bio->bi_disk;
    bpf_probe_read_kernel(&data.disk_name, sizeof(data.disk_name),
                       bio_disk->disk_name);
#ifdef KERNEL_STACK
    data.kernel_stack_id = stack_traces.get_stackid(ctx, 0);
#endif

#ifdef USER_STACK
    data.user_stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
#endif
    data.tgid_pid = GET_TGID;bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm_name, sizeof(data.comm_name));
    
    //counts.increment(data, bio->bi_iter.bi_size);
    u64 zleaf = 0;
    u64 *leaf = counts.lookup_or_try_init(&data, &zleaf);
    if (leaf)
        lock_xadd(leaf, bi_size);

    return 0;
}
"""

examples = """examples:
    ./iostack       # count bytes read or written by processes for all devices
    ./iostack -D 5  # trace only for 5 seconds
    ./iostack -K    # include kernel stacks
    ./iostack -U    # include user stacks
    ./iostack -K -f # Output in folded format for flame graphs
        """
parser = argparse.ArgumentParser(
    description="Count events and their stack traces",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

parser.add_argument("-D", "--duration",
                    help="total duration of trace, seconds",default=99999999)
parser.add_argument("-K", "--kernel-stack",
                    action="store_true", help="kernel stack only")
parser.add_argument("-U", "--user-stack",
                    action="store_true", help="user stack only")
parser.add_argument("-f", "--folded", action="store_true",
                    help="output folded format")
parser.add_argument("-P", "--perpid", action="store_true",
                    help="display stacks separately for each process")

args = parser.parse_args()

if args.user_stack:
    bpf_text = "#define USER_STACK\n" + bpf_text
if args.kernel_stack:
    bpf_text = "#define KERNEL_STACK\n" + bpf_text

# load BPF program
b = BPF(text=bpf_text)
if args.perpid:
    bpf_text = bpf_text.replace('GET_TGID', 'bpf_get_current_pid_tgid() >> 32')
else:
    bpf_text = bpf_text.replace('GET_TGID', '0xffffffff')
b.attach_kprobe(event="generic_make_request", fn_name="_generic_make_request")
matched = b.num_open_kprobes()
if matched == 0:
    print("error: 0 functions traced. Exiting.", file=stderr)
    exit(1)

duration = int(args.duration)
# header
if not args.folded:
    print("Tracing total io sizes (bytes) to block devices", end="")
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
        line = [k.comm_name.decode('utf-8', 'replace')] + \
                [b.sym(addr, k.tgid_pid).decode('utf-8', 'replace') for addr in
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

        if k.tgid_pid != 0xffffffff:
            print("    %s [%d]" % (k.comm_name.decode('utf-8', 'replace'), k.tgid_pid))
        else:
            print("    %s" % (k.comm_name.decode('utf-8', 'replace')))
        print("        %d\n" % v.value)

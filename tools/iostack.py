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
#include <linux/kernel.h>
#include <linux/bio.h>

struct disk_data_t {
    char disk_name[DISK_NAME_LEN];
    int kernel_stack_id;
    int user_stack_id;
    u64 tgid_pid;
    char comm_name[TASK_COMM_LEN];
};

struct io_cnt {
    u64 r_cnt;
    u64 w_cnt;
};

BPF_HASH(counts, struct disk_data_t, struct io_cnt);
BPF_STACK_TRACE(stack_traces, 16384);

int _generic_make_request(struct pt_regs *ctx, struct bio *bio) {
    struct disk_data_t data = {};
    int dir = op_is_write((bio)->bi_opf & REQ_OP_MASK) ? WRITE : READ;
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

#ifdef PERPID
    data.tgid_pid = bpf_get_current_pid_tgid() >> 32;
#else 
    data.tgid_pid = 0xffffffff;
#endif
    bpf_get_current_comm(&data.comm_name, sizeof(data.comm_name));
    
    struct io_cnt zleaf = {0};
    struct io_cnt *leaf = counts.lookup_or_try_init(&data, &zleaf);
    if (leaf) {
#if defined(TRACE_READ) || defined(TRACE_RW) 
        if (dir == READ)
            lock_xadd(&leaf->r_cnt, bi_size);
#endif
#if defined(TRACE_WRITE) || defined(TRACE_RW) 
        if (dir == WRITE)
            lock_xadd(&leaf->w_cnt, bi_size);
#endif
    }

    return 0;
}
"""

examples = """examples:
    ./iostack           # count bytes read or written by processes for all devices
    ./iostack -D 5      # trace only for 5 seconds
    ./iostack -K        # include kernel stacks
    ./iostack -U        # include user stacks
    ./iostack -K -f     # Output in folded format for flame graphs
    ./iostack -P        # Display stacks separately for each process
    ./iostack -K -io r  # Trace only reads
        """
parser = argparse.ArgumentParser(
    description="Count events and their stack traces",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

parser.add_argument("-D", "--duration",
                    help="total duration of trace, seconds", default=99999999)
parser.add_argument("-K", "--kernel-stack",
                    action="store_true", help="kernel stack only")
parser.add_argument("-U", "--user-stack",
                    action="store_true", help="user stack only")
parser.add_argument("-f", "--folded", action="store_true",
                    help="output folded format")
parser.add_argument("-P", "--perpid", action="store_true",
                    help="display stacks separately for each process")
parser.add_argument("-io", "--iodir", action="store", choices=["r", "w", "rw"],
                    default="rw", help="io dir to trace")

args = parser.parse_args()

if args.user_stack:
    bpf_text = "#define USER_STACK\n" + bpf_text
if args.kernel_stack:
    bpf_text = "#define KERNEL_STACK\n" + bpf_text
if args.perpid:
    bpf_text = "#define PER_PID\n" + bpf_text
if args.iodir == "r":
    bpf_text = "#define TRACE_READ\n" + bpf_text
if args.iodir == "w":
    bpf_text = "#define TRACE_WRITE\n" + bpf_text
if args.iodir == "rw":
    bpf_text = "#define TRACE_RW\n" + bpf_text

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
    print("Tracing io (bytes) to block devices", end="")
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

for k, v in sorted(counts.items(),
                   key=lambda counts: counts[1].r_cnt + counts[1].w_cnt):
    total_io_cnt = v.r_cnt + v.w_cnt
    if total_io_cnt == 0:
        continue

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
        print("%s %d" % (";".join(line), total_io_cnt))
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
            print("        %s [%d]" % (k.comm_name.decode('utf-8', 'replace'),
                                   k.tgid_pid))
        else:
            print("        %s" % (k.comm_name.decode('utf-8', 'replace')))
        print("        R: %d, W: %d\n" % (v.r_cnt, v.w_cnt))

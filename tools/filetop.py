#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# filetop  file reads and writes by process.
#          For Linux, uses BCC, eBPF.
#
# USAGE: filetop.py [-h] [-C] [-r MAXROWS] [interval] [count]
#
# This uses in-kernel eBPF maps to store per process summaries for efficiency.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 06-Feb-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import signal
from subprocess import call

# arguments
examples = """examples:
    ./filetop            # file I/O top, 1 second refresh
    ./filetop -C         # don't clear the screen
    ./filetop -p 181     # PID 181 only
    ./filetop 5          # 5 second summaries
    ./filetop 5 10       # 5 second summaries, 10 times only
"""
parser = argparse.ArgumentParser(
    description="File reads and writes by process",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-C", "--noclear", action="store_true",
    help="don't clear the screen")
parser.add_argument("-r", "--maxrows", default=20,
    help="maximum rows to print, default 20")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("interval", nargs="?", default=1,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
args = parser.parse_args()
interval = int(args.interval)
countdown = int(args.count)
maxrows = int(args.maxrows)
clear = not int(args.noclear)
debug = 0

# linux stats
loadavg = "/proc/loadavg"

# signal handler
def signal_ignore(signal, frame):
    print()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

#define MAX_FILE_LEN    32

// the key for the output summary
struct info_t {
    u32 pid;
    char name[TASK_COMM_LEN];
    char file[MAX_FILE_LEN];
    char type;
};

// the value of the output summary
struct val_t {
    u64 reads;
    u64 writes;
    u64 rbytes;
    u64 wbytes;
};

BPF_HASH(counts, struct info_t, struct val_t);

static int do_entry(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count, int is_read)
{
    u32 pid;

    pid = bpf_get_current_pid_tgid();
    if (FILTER)
        return 0;

    // skip I/O lacking a filename
    struct dentry *de = file->f_path.dentry;
    if (de->d_iname[0] == 0)
        return 0;

    // store counts and sizes by pid & file
    struct info_t info = {.pid = pid};
    bpf_get_current_comm(&info.name, sizeof(info.name));
    __builtin_memcpy(&info.file, de->d_iname, sizeof(info.file));
    int mode = file->f_inode->i_mode;
    if (S_ISREG(mode)) {
        info.type = 'R';
    } else if (S_ISSOCK(mode)) {
        info.type = 'S';
    } else {
        info.type = 'O';
    }

    struct val_t *valp, zero = {};
    valp = counts.lookup_or_init(&info, &zero);
    if (is_read) {
        valp->reads++;
        valp->rbytes += count;
    } else {
        valp->writes++;
        valp->wbytes += count;
    }

    return 0;
}

int trace_read_entry(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count)
{
    return do_entry(ctx, file, buf, count, 1);
}

int trace_write_entry(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count)
{
    return do_entry(ctx, file, buf, count, 0);
}

"""
if args.pid:
    bpf_text = bpf_text.replace('FILTER', 'pid != %s' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '0')
if debug:
    print(bpf_text)

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="__vfs_read", fn_name="trace_read_entry")
b.attach_kprobe(event="__vfs_write", fn_name="trace_write_entry")

print('Tracing... Output every %d secs. Hit Ctrl-C to end' % interval)

# output
exiting = 0
while 1:
    try:
        sleep(interval)
    except KeyboardInterrupt:
        exiting = 1

    # header
    if clear:
        call("clear")
    else:
        print()
    with open(loadavg) as stats:
        print("%-8s loadavg: %s" % (strftime("%H:%M:%S"), stats.read()))
    print("%-6s %-16s %-6s %-6s %-7s %-7s %1s %s" % ("PID", "COMM",
        "READS", "WRITES", "R_Kb", "W_Kb", "T", "FILE"))

    # by-PID output
    counts = b.get_table("counts")
    line = 0
    for k, v in reversed(sorted(counts.items(),
                                key=lambda counts: counts[1].rbytes)):

        # print line
        print("%-6d %-16s %-6d %-6d %-7d %-7d %1s %s" % (k.pid, k.name,
            v.reads, v.writes, v.rbytes / 1024, v.wbytes / 1024, k.type,
            k.file))

        line += 1
        if line >= maxrows:
            break
    counts.clear()

    countdown -= 1
    if exiting or countdown == 0:
        print("Detaching...")
        exit()

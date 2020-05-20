#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# dirtop  file reads and writes by directory.
#          For Linux, uses BCC, eBPF.
#
# USAGE: dirtop.py -d 'directory1,directory2' [-h] [-C] [-r MAXROWS] [interval] [count]
#
# This uses in-kernel eBPF maps to store per process summaries for efficiency.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Mar-2020   Erwan Velu      Created dirtop from filetop
# 06-Feb-2016   Brendan Gregg   Created filetop.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import os
import stat
from subprocess import call

# arguments
examples = """examples:
    ./dirtop -d '/hdfs/uuid/*/yarn'       # directory I/O top, 1 second refresh
    ./dirtop -d '/hdfs/uuid/*/yarn' -C    # don't clear the screen
    ./dirtop -d '/hdfs/uuid/*/yarn' 5     # 5 second summaries
    ./dirtop -d '/hdfs/uuid/*/yarn' 5 10  # 5 second summaries, 10 times only
    ./dirtop -d '/hdfs/uuid/*/yarn,/hdfs/uuid/*/data' # Running dirtop on two set of directories
"""
parser = argparse.ArgumentParser(
    description="File reads and writes by process",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-C", "--noclear", action="store_true",
                    help="don't clear the screen")
parser.add_argument("-r", "--maxrows", default=20,
                    help="maximum rows to print, default 20")
parser.add_argument("-s", "--sort", default="all",
                    choices=["all", "reads", "writes", "rbytes", "wbytes"],
                    help="sort column, default all")
parser.add_argument("-p", "--pid", type=int, metavar="PID", dest="tgid",
                    help="trace this PID only")
parser.add_argument("interval", nargs="?", default=1,
                    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
                    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
                    help=argparse.SUPPRESS)
parser.add_argument("-d", "--root-directories", type=str, required=True, dest="rootdirs",
                    help="select the directories to observe, separated by commas")
args = parser.parse_args()
interval = int(args.interval)
countdown = int(args.count)
maxrows = int(args.maxrows)
clear = not int(args.noclear)
debug = 0

# linux stats
loadavg = "/proc/loadavg"

# define BPF program
bpf_text = """
# include <uapi/linux/ptrace.h>
# include <linux/blkdev.h>

// the key for the output summary
struct info_t {
    unsigned long inode_id;
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
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    if (TGID_FILTER)
        return 0;

    // The directory inodes we look at
    u32 dir_ids[INODES_NUMBER] =  DIRECTORY_INODES;
    struct info_t info = {.inode_id = 0};
    struct dentry *pde = file->f_path.dentry;
    for (int i=0; i<50; i++) {
        // If we don't have any parent, we reached the root
        if (!pde->d_parent) {
            break;
        }
        pde = pde->d_parent;
        // Does the files is part of the directory we look for
        for(int dir_id=0; dir_id<INODES_NUMBER; dir_id++) {
            if (pde->d_inode->i_ino == dir_ids[dir_id]) {
                // Yes, let's export the top directory inode
                info.inode_id = pde->d_inode->i_ino;
                break;
            }
        }
    }
    // If we didn't found any, let's abort
    if (info.inode_id == 0) {
        return 0;
    }

    struct val_t *valp, zero = {};
    valp = counts.lookup_or_try_init(&info, &zero);
    if (valp) {
        if (is_read) {
            valp->reads++;
            valp->rbytes += count;
        } else {
            valp->writes++;
            valp->wbytes += count;
        }
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


def get_searched_ids(root_directories):
    """Export the inode numbers of the selected directories."""
    from glob import glob
    inode_to_path = {}
    inodes = "{"
    total_dirs = 0
    for root_directory in root_directories.split(','):
        searched_dirs = glob(root_directory, recursive=True)
        if not searched_dirs:
            continue

        for mydir in searched_dirs:
            total_dirs = total_dirs + 1
            # If we pass more than 15 dirs, ebpf program fails
            if total_dirs > 15:
                print('15 directories limit reached')
                break
            inode_id = os.lstat(mydir)[stat.ST_INO]
            if inode_id in inode_to_path:
                if inode_to_path[inode_id] == mydir:
                    print('Skipping {} as already considered'.format(mydir))
            else:
                inodes = "{},{}".format(inodes, inode_id)
                inode_to_path[inode_id] = mydir
                print('Considering {} with inode_id {}'.format(mydir, inode_id))

    inodes = inodes + '}'
    if len(inode_to_path) == 0:
        print('Cannot find any valid directory')
        exit()
    return inodes.replace('{,', '{'), inode_to_path


if args.tgid:
    bpf_text = bpf_text.replace('TGID_FILTER', 'tgid != %d' % args.tgid)
else:
    bpf_text = bpf_text.replace('TGID_FILTER', '0')

inodes, inodes_to_path = get_searched_ids(args.rootdirs)
bpf_text = bpf_text.replace("DIRECTORY_INODES", inodes)
bpf_text = bpf_text.replace(
    "INODES_NUMBER", '{}'.format(len(inodes.split(','))))

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="vfs_read", fn_name="trace_read_entry")
b.attach_kprobe(event="vfs_write", fn_name="trace_write_entry")

DNAME_INLINE_LEN = 32  # linux/dcache.h

print('Tracing... Output every %d secs. Hit Ctrl-C to end' % interval)


def sort_fn(counts):
    """Define how to sort the columns"""
    if args.sort == "all":
        return (counts[1].rbytes + counts[1].wbytes + counts[1].reads + counts[1].writes)
    else:
        return getattr(counts[1], args.sort)


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

    print("%-6s %-6s %-8s %-8s %s" %
          ("READS", "WRITES", "R_Kb", "W_Kb", "PATH"))
    # by-TID output
    counts = b.get_table("counts")
    line = 0
    reads = {}
    writes = {}
    reads_Kb = {}
    writes_Kb = {}
    for k, v in reversed(sorted(counts.items(),
                                key=sort_fn)):
        # If it's the first time we see this inode
        if k.inode_id not in reads:
            # let's create a new entry
            reads[k.inode_id] = v.reads
            writes[k.inode_id] = v.writes
            reads_Kb[k.inode_id] = v.rbytes / 1024
            writes_Kb[k.inode_id] = v.wbytes / 1024
        else:
            # unless add the current performance metrics
            # to the previous ones
            reads[k.inode_id] += v.reads
            writes[k.inode_id] += v.writes
            reads_Kb[k.inode_id] += v.rbytes / 1024
            writes_Kb[k.inode_id] += v.wbytes / 1024

    for node_id in reads:
        print("%-6d %-6d %-8d %-8d %s" %
              (reads[node_id], writes[node_id], reads_Kb[node_id], writes_Kb[node_id], inodes_to_path[node_id]))
        line += 1
        if line >= maxrows:
            break

    counts.clear()

    countdown -= 1
    if exiting or countdown == 0:
        print("Detaching...")
        exit()

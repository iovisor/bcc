#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# vfsrwcount  Count vfs_read, vfs_write bytes
#             per process per file

from __future__ import (
    absolute_import, division, print_function, unicode_literals)
from bcc import BPF
from time import sleep, strftime
from sys import argv


def usage():
    print("USAGE: %s [interval [count]]" % argv[0])
    exit()


# arguments
interval = 1
count = -1
if len(argv) > 1:
    try:
        interval = float(argv[1])
        if interval == 0:
            raise ValueError
        if len(argv) > 2:
            count = int(argv[2])
    except ValueError:  # also catches -h, --help
        usage()


# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>

struct vfs_ctx_t {
    pid_t pid;
    char comm[20];
    char file_name[20];
};

BPF_HASH(read_stats, struct vfs_ctx_t, int);
BPF_HASH(write_stats, struct vfs_ctx_t, int);

void do_read(struct pt_regs *ctx, struct file *file, char *buf, int count)
{
    struct vfs_ctx_t key = {};
    int *p_cnt;
    key.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    bpf_probe_read_str(
        &key.file_name, sizeof(key.file_name), file->f_path.dentry->d_iname);
    p_cnt = read_stats.lookup(&key);
    if (p_cnt)
        (*p_cnt)++;
    else
        read_stats.update(&key, &count);
}

void do_write(struct pt_regs *ctx, struct file *file, char *buf, int count)
{
    struct vfs_ctx_t key = {};
    int *p_cnt;
    key.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    bpf_probe_read_str(
        &key.file_name, sizeof(key.file_name), file->f_path.dentry->d_iname);
    p_cnt = write_stats.lookup(&key);
    if (p_cnt)
        (*p_cnt)++;
    else
        write_stats.update(&key, &count);
}
""")

b.attach_kprobe(event="vfs_read", fn_name="do_read")
b.attach_kprobe(event="vfs_write", fn_name="do_write")

# output
i = 0


try:
    while (1):
        if count > 0:
            i += 1
            if i > count:
                exit()
        sleep(interval)
        print("%s: " % strftime("%H:%M:%S"))
        print("read:")
        for r in b["read_stats"]:
            value = b["read_stats"][r].value
            print("[%d] [%s] [%s] [%d]" % (
                r.pid, r.comm, r.file_name, value))
        b["read_stats"].clear()
        print("write:")
        for w in b["write_stats"]:
            value = b["write_stats"][w].value
            print("[%d] [%s] [%s] [%d]" % (
                w.pid, w.comm, w.file_name, value))
        b["write_stats"].clear()
except KeyboardInterrupt:
    exit()

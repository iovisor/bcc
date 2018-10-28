#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# ttysnoop   Watch live output from a tty or pts device.
#            For Linux, uses BCC, eBPF. Embedded C.
#
# Due to a limited buffer size (see BUFSIZE), some commands (eg, a vim
# session) are likely to be printed a little messed up.
#
# Copyright (c) 2016 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# Idea: from ttywatcher.
#
# 15-Oct-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
import ctypes as ct
from subprocess import call
import argparse
from sys import argv
import sys
from os import stat

def usage():
    print("USAGE: %s [-Ch] {PTS | /dev/ttydev}  # try -h for help" % argv[0])
    exit()

# arguments
examples = """examples:
    ./ttysnoop /dev/pts/2    # snoop output from /dev/pts/2
    ./ttysnoop 2             # snoop output from /dev/pts/2 (shortcut)
    ./ttysnoop /dev/console  # snoop output from the system console
    ./ttysnoop /dev/tty0     # snoop output from /dev/tty0
"""
parser = argparse.ArgumentParser(
    description="Snoop output from a pts or tty device, eg, a shell",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-C", "--noclear", action="store_true",
    help="don't clear the screen")
parser.add_argument("device", default="-1",
    help="path to a tty device (eg, /dev/tty0) or pts number")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

if args.device == "-1":
    usage()

path = args.device
if path.find('/') != 0:
    path = "/dev/pts/" + path
try:
    pi = stat(path)
except:
    print("Unable to read device %s. Exiting." % path)
    exit()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>

#define BUFSIZE 256
struct data_t {
    int count;
    char buf[BUFSIZE];
};

BPF_PERF_OUTPUT(events);

int kprobe__tty_write(struct pt_regs *ctx, struct file *file,
    const char __user *buf, size_t count)
{
    if (file->f_inode->i_ino != PTS)
        return 0;

    // bpf_probe_read() can only use a fixed size, so truncate to count
    // in user space:
    struct data_t data = {};
    bpf_probe_read(&data.buf, BUFSIZE, (void *)buf);
    if (count > BUFSIZE)
        data.count = BUFSIZE;
    else
        data.count = count;
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
};
"""

bpf_text = bpf_text.replace('PTS', str(pi.st_ino))
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text)

BUFSIZE = 256

class Data(ct.Structure):
    _fields_ = [
        ("count", ct.c_int),
        ("buf", ct.c_char * BUFSIZE)
    ]

if not args.noclear:
    call("clear")

# process event
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print("%s" % event.buf[0:event.count].decode('utf-8', 'replace'), end="")
    sys.stdout.flush()

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()

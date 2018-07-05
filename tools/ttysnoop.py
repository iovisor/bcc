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
# 05-Jul-2018   Michael D. Day converted to a class

from __future__ import print_function
from bcc import BPF
import ctypes as ct
from subprocess import call
import argparse
from sys import argv
import sys
from os import stat



class Data(ct.Structure):
    BUFSIZE = 256
    _fields_ = [
        ("count", ct.c_int),
        ("buf", ct.c_char * BUFSIZE)
    ]

class ttysnoop_probe:
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

    def __init__(self, args, pi, debug = 0):
        self.bpf_text = self.bpf_text.replace('PTS', str(pi.st_ino))
        if debug or args.ebpf:
            print(self.bpf_text)
            if args.ebpf:
                exit()

        # initialize BPF

        b = BPF(text=self.bpf_text)

        if not args.noclear:
            call("clear")

        # process event
        def print_event(cpu, data, size):
            event = ct.cast(data, ct.POINTER(Data)).contents
            print("%s" % event.buf[0:event.count].decode(), end="")
            sys.stdout.flush()
        def print_event_json(cpu, data, size):
            event = ct.cast(data, ct.POINTER(Data)).contents
            line = event.buf[0:event.count].decode()
            line = line.rstrip('\n')
            print('{"line": %s}' %line)
            sys.stdout.flush()
        # loop with callback to print_event
        if args.json:
            b["events"].open_perf_buffer(print_event_json)
        else:
            b["events"].open_perf_buffer(print_event)
        while 1:
            b.perf_buffer_poll()


def usage():
    print("USAGE: %s [-Ch] {PTS | /dev/ttydev}  # try -h for help" % argv[0])
    exit()

def client_main(args):
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
    parser.add_argument("-j", "--json", action="store_true",
                        help="output json objects")
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
        if  args.json:
            print('{"result": Unable to read device %s. Exiting.}' % path)
        else:
            print("Unable to read device %s. Exiting." % path)
        exit()

    probe = ttysnoop_probe(args, pi)

if __name__ == "__main__":
    import argparse, sys
    client_main(sys.argv)
    sys.exit(0)

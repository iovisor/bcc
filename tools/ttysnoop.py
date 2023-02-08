#!/usr/bin/env python
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
# 13-Dec-2022   Rong Tao        Detect whether kfunc is supported.
# 07-Jan-2023   Rong Tao        Support ITER_UBUF(CO-RE way)

from __future__ import print_function
from bcc import BPF
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
    ./ttysnoop /dev/pts/2          # snoop output from /dev/pts/2
    ./ttysnoop 2                   # snoop output from /dev/pts/2 (shortcut)
    ./ttysnoop /dev/console        # snoop output from the system console
    ./ttysnoop /dev/tty0           # snoop output from /dev/tty0
    ./ttysnoop /dev/pts/2 -s 1024  # snoop output from /dev/pts/2 with data size 1024
    ./ttysnoop /dev/pts/2 -c 2     # snoop output from /dev/pts/2 with 2 checks for 256 bytes of data in buffer
                                     (potentially retrieving 512 bytes)
"""
parser = argparse.ArgumentParser(
    description="Snoop output from a pts or tty device, eg, a shell",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-C", "--noclear", action="store_true",
    help="don't clear the screen")
parser.add_argument("device", default="-1",
    help="path to a tty device (eg, /dev/tty0) or pts number")
parser.add_argument("-s", "--datasize", default="256",
    help="size of the transmitting buffer (default 256)")
parser.add_argument("-c", "--datacount", default="16",
    help="number of times we check for 'data-size' data (default 16)")
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
#include <linux/uio.h>

#define BUFSIZE USER_DATASIZE
struct data_t {
    int count;
    char buf[BUFSIZE];
};

BPF_ARRAY(data_map, struct data_t, 1);
PERF_TABLE

static int do_tty_write(void *ctx, const char __user *buf, size_t count)
{
    int zero = 0, i;
    struct data_t *data;

/* We can't read data to map data before v4.11 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
    struct data_t _data = {};

    data = &_data;
#else
    data = data_map.lookup(&zero);
    if (!data)
        return 0;
#endif

    #pragma unroll
    for (i = 0; i < USER_DATACOUNT; i++) {
        // bpf_probe_read_user() can only use a fixed size, so truncate to count
        // in user space:
        if (bpf_probe_read_user(&data->buf, BUFSIZE, (void *)buf))
            return 0;
        if (count > BUFSIZE)
            data->count = BUFSIZE;
        else
            data->count = count;
        PERF_OUTPUT_CTX
        if (count < BUFSIZE)
            return 0;
        count -= BUFSIZE;
        buf += BUFSIZE;
    }

    return 0;
};

/**
 * commit 9bb48c82aced (v5.11-rc4) tty: implement write_iter
 * changed arguments of tty_write function
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 11)
int kprobe__tty_write(struct pt_regs *ctx, struct file *file,
    const char __user *buf, size_t count)
{
    if (file->f_inode->i_ino != PTS)
        return 0;

    return do_tty_write(ctx, buf, count);
}
#else
PROBE_TTY_WRITE
{
    const char __user *buf = NULL;
    const struct kvec *kvec;
    size_t count = 0;

    if (iocb->ki_filp->f_inode->i_ino != PTS)
        return 0;
/**
 * commit 8cd54c1c8480 iov_iter: separate direction from flavour 
 * `type` is represented by iter_type and data_source seperately
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 14, 0)
    if (from->type != (ITER_IOVEC + WRITE))
        return 0;
#else
    if (ADD_FILTER_ITER_UBUF from->iter_type != ITER_IOVEC)
        return 0;
    if (from->data_source != WRITE)
        return 0;
#endif

    /* Support 'type' and 'iter_type' field name */
    switch (from->IOV_ITER_TYPE_NAME) {
    /**
     * <  5.14.0: case ITER_IOVEC + WRITE
     * >= 5.14.0: case ITER_IOVEC
     */
    case CASE_ITER_IOVEC_NAME:
        kvec  = from->kvec;
        buf   = kvec->iov_base;
        count = kvec->iov_len;
        break;
    CASE_ITER_UBUF_TEXT
    /* TODO: Support more type */
    default:
        break;
    }
    return do_tty_write(ctx, buf, count);
}
#endif
"""

probe_tty_write_kfunc = """
KFUNC_PROBE(tty_write, struct kiocb *iocb, struct iov_iter *from)
"""

probe_tty_write_kprobe = """
int kprobe__tty_write(struct pt_regs *ctx, struct kiocb *iocb,
    struct iov_iter *from)
"""

is_support_kfunc = BPF.support_kfunc()
if is_support_kfunc:
    bpf_text = bpf_text.replace('PROBE_TTY_WRITE', probe_tty_write_kfunc)
else:
    bpf_text = bpf_text.replace('PROBE_TTY_WRITE', probe_tty_write_kprobe)

if BPF.kernel_struct_has_field(b'iov_iter', b'iter_type') == 1:
    bpf_text = bpf_text.replace('IOV_ITER_TYPE_NAME', 'iter_type')
    bpf_text = bpf_text.replace('CASE_ITER_IOVEC_NAME', 'ITER_IOVEC')
else:
    bpf_text = bpf_text.replace('IOV_ITER_TYPE_NAME', 'type')
    bpf_text = bpf_text.replace('CASE_ITER_IOVEC_NAME', 'ITER_IOVEC + WRITE')

case_iter_ubuf_text = """
    case ITER_UBUF:
        buf   = from->ubuf;
        count = from->count;
        break;
"""

if BPF.kernel_struct_has_field(b'iov_iter', b'ubuf') == 1:
    bpf_text = bpf_text.replace('CASE_ITER_UBUF_TEXT', case_iter_ubuf_text)
    bpf_text = bpf_text.replace('ADD_FILTER_ITER_UBUF', 'from->iter_type != ITER_UBUF &&')
else:
    bpf_text = bpf_text.replace('CASE_ITER_UBUF_TEXT', '')
    bpf_text = bpf_text.replace('ADD_FILTER_ITER_UBUF', '')

if BPF.kernel_struct_has_field(b'bpf_ringbuf', b'waitq') == 1:
    PERF_MODE = "USE_BPF_RING_BUF"
    bpf_text = bpf_text.replace('PERF_TABLE',
                            'BPF_RINGBUF_OUTPUT(events, 64);')
    bpf_text = bpf_text.replace('PERF_OUTPUT_CTX',
                            'events.ringbuf_output(data, sizeof(*data), 0);')
else:
    PERF_MODE = "USE_BPF_PERF_BUF"
    bpf_text = bpf_text.replace('PERF_TABLE', 'BPF_PERF_OUTPUT(events);')
    bpf_text = bpf_text.replace('PERF_OUTPUT_CTX',
                            'events.perf_submit(ctx, data, sizeof(*data));')

bpf_text = bpf_text.replace('PTS', str(pi.st_ino))
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

bpf_text = bpf_text.replace('USER_DATASIZE', '%s' % args.datasize)
bpf_text = bpf_text.replace('USER_DATACOUNT', '%s' % args.datacount)

# initialize BPF
b = BPF(text=bpf_text)

if not args.noclear:
    call("clear")

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%s" % event.buf[0:event.count].decode('utf-8', 'replace'), end="")
    sys.stdout.flush()

# loop with callback to print_event
if PERF_MODE == "USE_BPF_RING_BUF":
    b["events"].open_ring_buffer(print_event)
else:
    b["events"].open_perf_buffer(print_event, page_cnt=64)

while 1:
    try:
        if PERF_MODE == "USE_BPF_RING_BUF":
            b.ring_buffer_poll()
        else:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

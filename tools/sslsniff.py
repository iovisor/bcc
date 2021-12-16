#!/usr/bin/python
#
# sslsniff  Captures data on read/recv or write/send functions of OpenSSL,
#           GnuTLS and NSS
#           For Linux, uses BCC, eBPF.
#
# USAGE: sslsniff.py [-h] [-p PID] [-u UID] [-x] [-c COMM] [-o] [-g] [-n] [-d]
#                    [--hexdump] [--max-buffer-size SIZE]
#
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 12-Aug-2016    Adrian Lopez   Created this.
# 13-Aug-2016    Mark Drayton   Fix SSL_Read
# 17-Aug-2016    Adrian Lopez   Capture GnuTLS and add options
#

from __future__ import print_function
from bcc import BPF
import argparse
import binascii
import textwrap

# arguments
examples = """examples:
    ./sslsniff              # sniff OpenSSL and GnuTLS functions
    ./sslsniff -p 181       # sniff PID 181 only
    ./sslsniff -u 1000      # sniff only UID 1000
    ./sslsniff -c curl      # sniff curl command only
    ./sslsniff --no-openssl # don't show OpenSSL calls
    ./sslsniff --no-gnutls  # don't show GnuTLS calls
    ./sslsniff --no-nss     # don't show NSS calls
    ./sslsniff --hexdump    # show data as hex instead of trying to decode it as UTF-8
    ./sslsniff -x           # show process UID and TID
"""
parser = argparse.ArgumentParser(
    description="Sniff SSL data",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", type=int, help="sniff this PID only.")
parser.add_argument("-u", "--uid", type=int, default=None,
                    help="sniff this UID only.")
parser.add_argument("-x", "--extra", action="store_true",
                    help="show extra fields (UID, TID)")
parser.add_argument("-c", "--comm",
                    help="sniff only commands matching string.")
parser.add_argument("-o", "--no-openssl", action="store_false", dest="openssl",
                    help="do not show OpenSSL calls.")
parser.add_argument("-g", "--no-gnutls", action="store_false", dest="gnutls",
                    help="do not show GnuTLS calls.")
parser.add_argument("-n", "--no-nss", action="store_false", dest="nss",
                    help="do not show NSS calls.")
parser.add_argument('-d', '--debug', dest='debug', action='count', default=0,
                    help='debug mode.')
parser.add_argument("--ebpf", action="store_true",
                    help=argparse.SUPPRESS)
parser.add_argument("--hexdump", action="store_true", dest="hexdump",
                    help="show data as hexdump instead of trying to decode it as UTF-8")
parser.add_argument('--max-buffer-size', type=int, default=8192,
                    help='Size of captured buffer')
args = parser.parse_args()


prog = """
#include <linux/ptrace.h>
#include <linux/sched.h>        /* For TASK_COMM_LEN */

#define MAX_BUF_SIZE __MAX_BUF_SIZE__

struct probe_SSL_data_t {
        u64 timestamp_ns;
        u32 pid;
        u32 tid;
        u32 uid;
        u32 len;
        int buf_filled;
        char comm[TASK_COMM_LEN];
        u8 buf[MAX_BUF_SIZE];
};

#define BASE_EVENT_SIZE ((size_t)(&((struct probe_SSL_data_t*)0)->buf))
#define EVENT_SIZE(X) (BASE_EVENT_SIZE + ((size_t)(X)))


BPF_PERCPU_ARRAY(ssl_data, struct probe_SSL_data_t, 1);
BPF_PERF_OUTPUT(perf_SSL_write);

int probe_SSL_write(struct pt_regs *ctx, void *ssl, void *buf, int num) {
        int ret;
        u32 zero = 0;
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = pid_tgid;
        u32 uid = bpf_get_current_uid_gid();

        PID_FILTER
        UID_FILTER
        struct probe_SSL_data_t *data = ssl_data.lookup(&zero);
        if (!data)
                return 0;

        data->timestamp_ns = bpf_ktime_get_ns();
        data->pid = pid;
        data->tid = tid;
        data->uid = uid;
        data->len = num;
        data->buf_filled = 0;
        bpf_get_current_comm(&data->comm, sizeof(data->comm));
        u32 buf_copy_size = min((size_t)MAX_BUF_SIZE, (size_t)num);

        if (buf != 0)
                ret = bpf_probe_read_user(data->buf, buf_copy_size, buf);

        if (!ret)
                data->buf_filled = 1;
        else
                buf_copy_size = 0;

        perf_SSL_write.perf_submit(ctx, data, EVENT_SIZE(buf_copy_size));
        return 0;
}

BPF_PERF_OUTPUT(perf_SSL_read);

BPF_HASH(bufs, u32, u64);

int probe_SSL_read_enter(struct pt_regs *ctx, void *ssl, void *buf, int num) {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;
        u32 uid = bpf_get_current_uid_gid();

        PID_FILTER
        UID_FILTER

        bufs.update(&tid, (u64*)&buf);
        return 0;
}

int probe_SSL_read_exit(struct pt_regs *ctx, void *ssl, void *buf, int num) {
        u32 zero = 0;
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;
        u32 uid = bpf_get_current_uid_gid();
        int ret;

        PID_FILTER
        UID_FILTER

        u64 *bufp = bufs.lookup(&tid);
        if (bufp == 0)
                return 0;

        int len = PT_REGS_RC(ctx);
        if (len <= 0) // read failed
                return 0;

        struct probe_SSL_data_t *data = ssl_data.lookup(&zero);
        if (!data)
                return 0;

        data->timestamp_ns = bpf_ktime_get_ns();
        data->pid = pid;
        data->tid = tid;
        data->uid = uid;
        data->len = (u32)len;
        data->buf_filled = 0;
        u32 buf_copy_size = min((size_t)MAX_BUF_SIZE, (size_t)len);

        bpf_get_current_comm(&data->comm, sizeof(data->comm));

        if (bufp != 0)
                ret = bpf_probe_read_user(&data->buf, buf_copy_size, (char *)*bufp);

        bufs.delete(&tid);

        if (!ret)
                data->buf_filled = 1;
        else
                buf_copy_size = 0;

        perf_SSL_read.perf_submit(ctx, data, EVENT_SIZE(buf_copy_size));
        return 0;
}
"""

if args.pid:
    prog = prog.replace('PID_FILTER', 'if (pid != %d) { return 0; }' % args.pid)
else:
    prog = prog.replace('PID_FILTER', '')

if args.uid is not None:
    prog = prog.replace('UID_FILTER', 'if (uid != %d) { return 0; }' % args.uid)
else:
    prog = prog.replace('UID_FILTER', '')

prog = prog.replace('__MAX_BUF_SIZE__', str(args.max_buffer_size))

if args.debug or args.ebpf:
    print(prog)
    if args.ebpf:
        exit()


b = BPF(text=prog)

# It looks like SSL_read's arguments aren't available in a return probe so you
# need to stash the buffer address in a map on the function entry and read it
# on its exit (Mark Drayton)
#
if args.openssl:
    b.attach_uprobe(name="ssl", sym="SSL_write", fn_name="probe_SSL_write",
                    pid=args.pid or -1)
    b.attach_uprobe(name="ssl", sym="SSL_read", fn_name="probe_SSL_read_enter",
                    pid=args.pid or -1)
    b.attach_uretprobe(name="ssl", sym="SSL_read",
                       fn_name="probe_SSL_read_exit", pid=args.pid or -1)

if args.gnutls:
    b.attach_uprobe(name="gnutls", sym="gnutls_record_send",
                    fn_name="probe_SSL_write", pid=args.pid or -1)
    b.attach_uprobe(name="gnutls", sym="gnutls_record_recv",
                    fn_name="probe_SSL_read_enter", pid=args.pid or -1)
    b.attach_uretprobe(name="gnutls", sym="gnutls_record_recv",
                       fn_name="probe_SSL_read_exit", pid=args.pid or -1)

if args.nss:
    b.attach_uprobe(name="nspr4", sym="PR_Write", fn_name="probe_SSL_write",
                    pid=args.pid or -1)
    b.attach_uprobe(name="nspr4", sym="PR_Send", fn_name="probe_SSL_write",
                    pid=args.pid or -1)
    b.attach_uprobe(name="nspr4", sym="PR_Read", fn_name="probe_SSL_read_enter",
                    pid=args.pid or -1)
    b.attach_uretprobe(name="nspr4", sym="PR_Read",
                       fn_name="probe_SSL_read_exit", pid=args.pid or -1)
    b.attach_uprobe(name="nspr4", sym="PR_Recv", fn_name="probe_SSL_read_enter",
                    pid=args.pid or -1)
    b.attach_uretprobe(name="nspr4", sym="PR_Recv",
                       fn_name="probe_SSL_read_exit", pid=args.pid or -1)

# define output data structure in Python


# header
header = "%-12s %-18s %-16s %-7s %-6s" % ("FUNC", "TIME(s)", "COMM", "PID", "LEN")

if args.extra:
    header += " %-7s %-7s" % ("UID", "TID")

print(header)
# process event
start = 0


def print_event_write(cpu, data, size):
    print_event(cpu, data, size, "WRITE/SEND", "perf_SSL_write")


def print_event_read(cpu, data, size):
    print_event(cpu, data, size, "READ/RECV", "perf_SSL_read")


def print_event(cpu, data, size, rw, evt):
    global start
    event = b[evt].event(data)
    if event.len <= args.max_buffer_size:
        buf_size = event.len
    else:
        buf_size = args.max_buffer_size

    if event.buf_filled == 1:
        buf = bytearray(event.buf[:buf_size])
    else:
        buf_size = 0
        buf = b""

    # Filter events by command
    if args.comm:
        if not args.comm == event.comm.decode('utf-8', 'replace'):
            return

    if start == 0:
        start = event.timestamp_ns
    time_s = (float(event.timestamp_ns - start)) / 1000000000

    s_mark = "-" * 5 + " DATA " + "-" * 5

    e_mark = "-" * 5 + " END DATA " + "-" * 5

    truncated_bytes = event.len - buf_size
    if truncated_bytes > 0:
        e_mark = "-" * 5 + " END DATA (TRUNCATED, " + str(truncated_bytes) + \
                " bytes lost) " + "-" * 5

    base_fmt = "%(func)-12s %(time)-18.9f %(comm)-16s %(pid)-7d %(len)-6d"

    if args.extra:
        base_fmt += " %(uid)-7d %(tid)-7d"

    fmt = ''.join([base_fmt, "\n%(begin)s\n%(data)s\n%(end)s\n\n"])
    if args.hexdump:
        unwrapped_data = binascii.hexlify(buf)
        data = textwrap.fill(unwrapped_data.decode('utf-8', 'replace'), width=32)
    else:
        data = buf.decode('utf-8', 'replace')

    fmt_data = {
        'func': rw,
        'time': time_s,
        'comm': event.comm.decode('utf-8', 'replace'),
        'pid': event.pid,
        'tid': event.tid,
        'uid': event.uid,
        'len': event.len,
        'begin': s_mark,
        'end': e_mark,
        'data': data
    }

    print(fmt % fmt_data)


b["perf_SSL_write"].open_perf_buffer(print_event_write)
b["perf_SSL_read"].open_perf_buffer(print_event_read)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

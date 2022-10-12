#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
# 
# undump        Dump UNIX socket packets.
#               For Linux, uses BCC, eBPF. Embedded C.
# USAGE: undump [-h] [-t] [-p PID]
#
# This uses dynamic tracing of kernel functions, and will need to be updated
# to match kernel changes.
#
# Copyright (c) 2021 Rong Tao.
# Licensed under the GPL License, Version 2.0
#
# 27-Aug-2021   Rong Tao   Created this.
# 17-Sep-2021   Rong Tao   Simplify according to chenhengqi's suggestion
#                           https://github.com/iovisor/bcc/pull/3615
#
from __future__ import print_function
from bcc import BPF
from bcc.containers import filter_by_containers
from bcc.utils import printb
import argparse
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
from time import sleep
from datetime import datetime
import sys

# arguments
examples = """examples:
    ./undump           # trace/dump all UNIX packets
    ./undump -p 181    # only trace/dump PID 181
"""
parser = argparse.ArgumentParser(
    description="Dump UNIX socket packets",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
    
parser.add_argument("-p", "--pid",
        help="trace this PID only")
args = parser.parse_args()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/aio.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/module.h>
#include <net/sock.h>
#include <net/af_unix.h>

#define MAX_PKT 512
struct recv_data_t {
    u32 recv_len;
    u8  pkt[MAX_PKT];
};

// single element per-cpu array to hold the current event off the stack
BPF_PERCPU_ARRAY(unix_data, struct recv_data_t, 1);

BPF_PERF_OUTPUT(unix_recv_events);

int trace_unix_stream_read_actor(struct pt_regs *ctx)
{
    u32 zero = 0;
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;

    FILTER_PID

	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);

    struct recv_data_t *data = unix_data.lookup(&zero);
    if (!data) 
        return 0;

    unsigned int data_len = skb->len;
    if(data_len > MAX_PKT)
        return 0;
        
    void *iodata = (void *)skb->data;
    data->recv_len = data_len;
    
    bpf_probe_read(data->pkt, data_len, iodata);
    unix_recv_events.perf_submit(ctx, data, data_len+sizeof(u32));
    
    return 0;
}
"""

if args.pid:
    bpf_text = bpf_text.replace('FILTER_PID',
        'if (pid != %s) { return 0; }' % args.pid)

bpf_text = bpf_text.replace('FILTER_PID', '')

# process event
def print_recv_pkg(cpu, data, size):
    event = b["unix_recv_events"].event(data)
    if args.pid:
        print("PID \033[1;31m%s\033[m " % args.pid, end="")
    print("Recv \033[1;31m%d\033[m bytes" % event.recv_len)

    print("    ", end="")
    for i in range(0, event.recv_len):
        print("%02x " % event.pkt[i], end="")
        sys.stdout.flush()
        if (i+1)%16 == 0:
            print("")
            print("    ", end="")
    print("")

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="unix_stream_read_actor", fn_name="trace_unix_stream_read_actor")

if args.pid:
    print("Tracing \033[1;31mPID=%s\033[m UNIX socket packets ... Hit Ctrl-C to end" % args.pid)
else:
    print("Tracing UNIX socket packets ... Hit Ctrl-C to end")

start_ts = 0

# read events
b["unix_recv_events"].open_perf_buffer(print_recv_pkg)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

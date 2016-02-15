#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# tcpretrans    Trace TCP retransmits and TLPs.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpretrans [-h] [-l]
#
# This uses dynamic tracing of kernel functions, and will need to be updated
# to match kernel changes.
#
# IPv4 addresses are printed as dotted quads. For IPv6 addresses, the last four
# bytes are printed after "..."; check for future versions with better IPv6
# support.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Feb-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime
import ctypes as ct

# arguments
examples = """examples:
    ./tcpretrans           # trace TCP retransmits
    ./tcpretrans -l        # include TLP attempts
"""
parser = argparse.ArgumentParser(
    description="Trace TCP retransmits",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-l", "--lossprobe", action="store_true",
    help="include tail loss probe attempts")
args = parser.parse_args()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define RETRANSMIT  1
#define TLP         2

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    // XXX: switch some to u32's when supported
    u64 pid;
    u64 ip;
    u64 saddr;
    u64 daddr;
    u64 lport;
    u64 dport;
    u64 state;
    u64 type;
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    // XXX: update to transfer full ipv6 addrs
    u64 pid;
    u64 ip;
    u64 saddr;
    u64 daddr;
    u64 lport;
    u64 dport;
    u64 state;
    u64 type;
};
BPF_PERF_OUTPUT(ipv6_events);

static int trace_event(struct pt_regs *ctx, struct sock *sk, int type)
{
    if (sk == NULL)
        return 0;
    u32 pid = bpf_get_current_pid_tgid();
    struct sock *skp = NULL;
    bpf_probe_read(&skp, sizeof(skp), &sk);

    // pull in details
    u16 family = 0, lport = 0, dport = 0;
    char state = 0;
    bpf_probe_read(&family, sizeof(family), &skp->__sk_common.skc_family);
    bpf_probe_read(&lport, sizeof(lport), &skp->__sk_common.skc_num);
    bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);
    bpf_probe_read(&state, sizeof(state), (void *)&skp->__sk_common.skc_state);

    if (family == AF_INET) {
        struct ipv4_data_t data4 = {.pid = pid, .ip = 4, .type = type};
        bpf_probe_read(&data4.saddr, sizeof(u32),
            &skp->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&data4.daddr, sizeof(u32),
            &skp->__sk_common.skc_daddr);
        data4.lport = lport;
        data4.dport = dport;
        data4.state = state;
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));

    } else if (family == AF_INET6) {
        struct ipv6_data_t data6 = {.pid = pid, .ip = 6, .type = type};
        // just grab the last 4 bytes for now
        u32 saddr = 0, daddr = 0;
        bpf_probe_read(&saddr, sizeof(saddr),
            &skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[3]);
        bpf_probe_read(&daddr, sizeof(daddr),
            &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32[3]);
        data6.saddr = bpf_ntohl(saddr);
        data6.daddr = bpf_ntohl(daddr);
        data6.lport = lport;
        data6.dport = dport;
        data6.state = state;
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }
    // else drop

    return 0;
}

int trace_retransmit(struct pt_regs *ctx, struct sock *sk)
{
    trace_event(ctx, sk, RETRANSMIT);
    return 0;
}

int trace_tlp(struct pt_regs *ctx, struct sock *sk)
{
    trace_event(ctx, sk, TLP);
    return 0;
}
"""

# event data
TASK_COMM_LEN = 16      # linux/sched.h
class Data_ipv4(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulonglong),
        ("ip", ct.c_ulonglong),
        ("saddr", ct.c_ulonglong),
        ("daddr", ct.c_ulonglong),
        ("lport", ct.c_ulonglong),
        ("dport", ct.c_ulonglong),
        ("state", ct.c_ulonglong),
        ("type", ct.c_ulonglong)
    ]
class Data_ipv6(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulonglong),
        ("ip", ct.c_ulonglong),
        ("saddr", ct.c_ulonglong),
        ("daddr", ct.c_ulonglong),
        ("lport", ct.c_ulonglong),
        ("dport", ct.c_ulonglong),
        ("state", ct.c_ulonglong),
        ("type", ct.c_ulonglong)
    ]

# from bpf_text:
type = {}
type[1] = 'R'
type[2] = 'L'

def inet_ntoa(addr):
    dq = ''
    for i in range(0, 4):
        dq = dq + str(addr & 0xff)
        if (i != 3):
            dq = dq + '.'
        addr = addr >> 8
    return dq

# from include/net/tcp_states.h:
tcpstate = {}
tcpstate[1] = 'ESTABLISHED'
tcpstate[2] = 'SYN_SENT'
tcpstate[3] = 'SYN_RECV'
tcpstate[4] = 'FIN_WAIT1'
tcpstate[5] = 'FIN_WAIT2'
tcpstate[6] = 'TIME_WAIT'
tcpstate[7] = 'CLOSE'
tcpstate[8] = 'CLOSE_WAIT'
tcpstate[9] = 'LAST_ACK'
tcpstate[10] = 'LISTEN'
tcpstate[11] = 'CLOSING'
tcpstate[12] = 'NEW_SYN_RECV'

# process event
def print_ipv4_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv4)).contents
    print("%-8s %-6d %-2d %-20s %1s> %-20s %s" % (
        strftime("%H:%M:%S"), event.pid, event.ip,
        "%s:%s" % (inet_ntoa(event.saddr), event.lport),
        type[event.type],
        "%s:%s" % (inet_ntoa(event.daddr), event.dport),
        tcpstate[event.state]))
def print_ipv6_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv6)).contents
    print("%%-8s -6d %-2d %-20s %1s> %-20s %s" % (
        strftime("%H:%M:%S"), event.pid, event.ip,
        "...%x:%d" % (event.saddr, event.lport),
        type[event.type],
        "...%x:%d" % (event.daddr, event.dport),
        tcpstate[event.state]))

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_retransmit_skb", fn_name="trace_retransmit")
b.attach_kprobe(event="tcp_send_loss_probe", fn_name="trace_tlp")

# header
print("%-8s %-6s %-2s %-20s %1s> %-20s %-4s" % ("TIME", "PID", "IP",
    "LADDR:LPORT", "T", "RADDR:RPORT", "STATE"))

# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
b["ipv6_events"].open_perf_buffer(print_ipv6_event)
while 1:
    b.kprobe_poll()

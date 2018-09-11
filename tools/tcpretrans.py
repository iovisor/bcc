#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# tcpretrans    Trace or count TCP retransmits and TLPs.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpretrans [-c] [-h] [-l]
#
# This uses dynamic tracing of kernel functions, and will need to be updated
# to match kernel changes.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Feb-2016   Brendan Gregg   Created this.
# 03-Nov-2017   Matthias Tafelmeier Extended this.

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
import ctypes as ct
from time import sleep

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
parser.add_argument("-c", "--count", action="store_true",
    help="count occurred retransmits per flow")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define RETRANSMIT  1
#define TLP         2

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u32 pid;
    u64 ip;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    u64 state;
    u64 type;
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u32 pid;
    u64 ip;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 lport;
    u16 dport;
    u64 state;
    u64 type;
};
BPF_PERF_OUTPUT(ipv6_events);

// separate flow keys per address family
struct ipv4_flow_key_t {
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
};
BPF_HASH(ipv4_count, struct ipv4_flow_key_t);

struct ipv6_flow_key_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 lport;
    u16 dport;
};
BPF_HASH(ipv6_count, struct ipv6_flow_key_t);

static int trace_event(struct pt_regs *ctx, struct sock *skp, int type)
{
    if (skp == NULL)
        return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // pull in details
    u16 family = skp->__sk_common.skc_family;
    u16 lport = skp->__sk_common.skc_num;
    u16 dport = skp->__sk_common.skc_dport;
    char state = skp->__sk_common.skc_state;

    if (family == AF_INET) {
        IPV4_INIT
        IPV4_CORE
    } else if (family == AF_INET6) {
        IPV6_INIT
        IPV6_CORE
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

struct_init = { 'ipv4':
        { 'count' :
            """
               struct ipv4_flow_key_t flow_key = {};
               flow_key.saddr = skp->__sk_common.skc_rcv_saddr;
               flow_key.daddr = skp->__sk_common.skc_daddr;
               // lport is host order
               flow_key.lport = lport;
               flow_key.dport = ntohs(dport);""",
               'trace' :
               """
               struct ipv4_data_t data4 = {};
               data4.pid = pid;
               data4.ip = 4;
               data4.type = type;
               data4.saddr = skp->__sk_common.skc_rcv_saddr;
               data4.daddr = skp->__sk_common.skc_daddr;
               // lport is host order
               data4.lport = lport;
               data4.dport = ntohs(dport);
               data4.state = state; """
               },
        'ipv6':
        { 'count' :
            """
                    struct ipv6_flow_key_t flow_key = {};
                    bpf_probe_read(&flow_key.saddr, sizeof(flow_key.saddr),
                        skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
                    bpf_probe_read(&flow_key.daddr, sizeof(flow_key.daddr),
                        skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
                    // lport is host order
                    flow_key.lport = lport;
                    flow_key.dport = ntohs(dport);""",
          'trace' : """
                    struct ipv6_data_t data6 = {};
                    data6.pid = pid;
                    data6.ip = 6;
                    data6.type = type;
                    bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
                        skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
                    bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
                        skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
                    // lport is host order
                    data6.lport = lport;
                    data6.dport = ntohs(dport);
                    data6.state = state;"""
                }
        }

count_core_base = """
        COUNT_STRUCT.increment(flow_key);
"""

if args.count:
    bpf_text = bpf_text.replace("IPV4_INIT", struct_init['ipv4']['count'])
    bpf_text = bpf_text.replace("IPV6_INIT", struct_init['ipv6']['count'])
    bpf_text = bpf_text.replace("IPV4_CORE", count_core_base.replace("COUNT_STRUCT", 'ipv4_count'))
    bpf_text = bpf_text.replace("IPV6_CORE", count_core_base.replace("COUNT_STRUCT", 'ipv6_count'))
else:
    bpf_text = bpf_text.replace("IPV4_INIT", struct_init['ipv4']['trace'])
    bpf_text = bpf_text.replace("IPV6_INIT", struct_init['ipv6']['trace'])
    bpf_text = bpf_text.replace("IPV4_CORE", "ipv4_events.perf_submit(ctx, &data4, sizeof(data4));")
    bpf_text = bpf_text.replace("IPV6_CORE", "ipv6_events.perf_submit(ctx, &data6, sizeof(data6));")

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# event data
class Data_ipv4(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("ip", ct.c_ulonglong),
        ("saddr", ct.c_uint),
        ("daddr", ct.c_uint),
        ("lport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("state", ct.c_ulonglong),
        ("type", ct.c_ulonglong)
    ]

class Data_ipv6(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("ip", ct.c_ulonglong),
        ("saddr", (ct.c_ulonglong * 2)),
        ("daddr", (ct.c_ulonglong * 2)),
        ("lport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("state", ct.c_ulonglong),
        ("type", ct.c_ulonglong)
    ]

# from bpf_text:
type = {}
type[1] = 'R'
type[2] = 'L'

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
        "%s:%d" % (inet_ntop(AF_INET, pack('I', event.saddr)), event.lport),
        type[event.type],
        "%s:%s" % (inet_ntop(AF_INET, pack('I', event.daddr)), event.dport),
        tcpstate[event.state]))

def print_ipv6_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv6)).contents
    print("%-8s %-6d %-2d %-20s %1s> %-20s %s" % (
        strftime("%H:%M:%S"), event.pid, event.ip,
        "%s:%d" % (inet_ntop(AF_INET6, event.saddr), event.lport),
        type[event.type],
        "%s:%d" % (inet_ntop(AF_INET6, event.daddr), event.dport),
        tcpstate[event.state]))

def depict_cnt(counts_tab, l3prot='ipv4'):
    for k, v in sorted(counts_tab.items(), key=lambda counts: counts[1].value):
        depict_key = ""
        ep_fmt = "[%s]#%d"
        if l3prot == 'ipv4':
            depict_key = "%-20s <-> %-20s" % (ep_fmt % (inet_ntop(AF_INET, pack('I', k.saddr)), k.lport),
                                              ep_fmt % (inet_ntop(AF_INET, pack('I', k.daddr)), k.dport))
        else:
            depict_key = "%-20s <-> %-20s" % (ep_fmt % (inet_ntop(AF_INET6, k.saddr), k.lport),
                                              ep_fmt % (inet_ntop(AF_INET6, k.daddr), k.dport))

        print ("%s %10d" % (depict_key, v.value))

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_retransmit_skb", fn_name="trace_retransmit")
if args.lossprobe:
    b.attach_kprobe(event="tcp_send_loss_probe", fn_name="trace_tlp")

print("Tracing retransmits ... Hit Ctrl-C to end")
if args.count:
    try:
        while 1:
            sleep(99999999)
    except BaseException:
        pass

    # header
    print("\n%-25s %-25s %-10s" % (
        "LADDR:LPORT", "RADDR:RPORT", "RETRANSMITS"))
    depict_cnt(b.get_table("ipv4_count"))
    depict_cnt(b.get_table("ipv6_count"), l3prot='ipv6')
# read events
else:
    # header
    print("%-8s %-6s %-2s %-20s %1s> %-20s %-4s" % ("TIME", "PID", "IP",
        "LADDR:LPORT", "T", "RADDR:RPORT", "STATE"))
    b["ipv4_events"].open_perf_buffer(print_ipv4_event)
    b["ipv6_events"].open_perf_buffer(print_ipv6_event)
    while 1:
        b.perf_buffer_poll()

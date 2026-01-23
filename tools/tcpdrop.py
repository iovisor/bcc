#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# tcpdrop   Trace TCP kernel-dropped packets/segments.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# This provides information such as packet details, socket state, and kernel
# stack trace for packets/segments that were dropped via tcp_drop().
#
# USAGE: tcpdrop [-4 | -6] [-h]
#
# This uses dynamic tracing of kernel functions, and will need to be updated
# to match kernel changes.
#
# Copyright 2018 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 30-May-2018   Brendan Gregg   Created this.
# 15-Jun-2022   Rong Tao        Add tracepoint:skb:kfree_skb
# 23-Mar-2025   Lance Yang      Dump drop reason

from __future__ import print_function
from bcc import BPF
import argparse
import os
from time import strftime
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import sleep
from bcc import tcp

# arguments
examples = """examples:
    ./tcpdrop           # trace kernel TCP drops
    ./tcpdrop -4        # trace IPv4 family only
    ./tcpdrop -6        # trace IPv6 family only
"""
parser = argparse.ArgumentParser(
    description="Trace TCP drops by the kernel",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
group = parser.add_mutually_exclusive_group()
group.add_argument("-4", "--ipv4", action="store_true",
    help="trace IPv4 family only")
group.add_argument("-6", "--ipv6", action="store_true",
    help="trace IPv6 family only")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
parser.add_argument("--netns-id", type=int,
    help="the netns id to filter by", default=0)
parser.add_argument("--pid-netns",
    help="the pid whose netns to filter by", type=int, default=0)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/ip.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>

BPF_STACK_TRACE(stack_traces, 1024);

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u32 pid;
    u64 ip;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 state;
    u8 tcpflags;
    u32 stack_id;
    u32 drop_reason;
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u32 pid;
    u64 ip;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 sport;
    u16 dport;
    u8 state;
    u8 tcpflags;
    u32 stack_id;
    u32 drop_reason;
};
BPF_PERF_OUTPUT(ipv6_events);

static struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in tcp_hdr() -> skb_transport_header().
    return (struct tcphdr *)(skb->head + skb->transport_header);
}

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in ip_hdr() -> skb_network_header().
    return (struct iphdr *)(skb->head + skb->network_header);
}

// from include/net/tcp.h:
#ifndef tcp_flag_byte
#define tcp_flag_byte(th) (((u_int8_t *)th)[13])
#endif

static int __trace_tcp_drop(void *ctx, struct sock *sk, struct sk_buff *skb, u32 reason)
{
    if (sk == NULL)
        return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // pull in details from the packet headers and the sock struct
    u16 family = sk->__sk_common.skc_family;
    char state = sk->__sk_common.skc_state;
    u16 sport = 0, dport = 0;
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct iphdr *ip = skb_to_iphdr(skb);
    u8 tcpflags = ((u_int8_t *)tcp)[13];
    sport = tcp->source;
    dport = tcp->dest;
    sport = ntohs(sport);
    dport = ntohs(dport);

    FILTER_FAMILY

    FILTER_NETNS

    if (family == AF_INET) {
        struct ipv4_data_t data4 = {};
        data4.pid = pid;
        data4.ip = 4;
        data4.saddr = ip->saddr;
        data4.daddr = ip->daddr;
        data4.dport = dport;
        data4.sport = sport;
        data4.state = state;
        data4.tcpflags = tcpflags;
        data4.stack_id = stack_traces.get_stackid(ctx, 0);
        data4.drop_reason = reason;
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));

    } else if (family == AF_INET6) {
        struct ipv6_data_t data6 = {};
        data6.pid = pid;
        data6.ip = 6;
        // The remote address (skc_v6_daddr) was the source
        bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr),
            sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        // The local address (skc_v6_rcv_saddr) was the destination
        bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr),
            sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        data6.dport = dport;
        data6.sport = sport;
        data6.state = state;
        data6.tcpflags = tcpflags;
        data6.stack_id = stack_traces.get_stackid(ctx, 0);
        data6.drop_reason = reason;
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }
    // else drop

    return 0;
}

int trace_tcp_drop(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb)
{
    // tcp_drop() does not supply a drop reason.
    return __trace_tcp_drop(ctx, sk, skb, SKB_DROP_REASON_NOT_SPECIFIED);
}
"""

bpf_kfree_skb_text = """

TRACEPOINT_PROBE(skb, kfree_skb) {
    struct sk_buff *skb = args->skbaddr;
    struct sock *sk = skb->sk;
    enum skb_drop_reason reason = args->reason;

    // SKB_NOT_DROPPED_YET,
    // SKB_DROP_REASON_NOT_SPECIFIED,
    if (reason > SKB_DROP_REASON_NOT_SPECIFIED) {
        return __trace_tcp_drop(args, sk, skb, (u32)reason);
    }

    return 0;
}
"""

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()
if args.ipv4:
    bpf_text = bpf_text.replace('FILTER_FAMILY',
        'if (family != AF_INET) { return 0; }')
elif args.ipv6:
    bpf_text = bpf_text.replace('FILTER_FAMILY',
        'if (family != AF_INET6) { return 0; }')
else:
    bpf_text = bpf_text.replace('FILTER_FAMILY', '')

if args.pid_netns != 0:
    if args.netns_id != 0:
        print("ERROR: --pid_netns and --netns-id not allowed together")
        exit(1)
    args.netns_id = os.stat('/proc/{}/ns/net'.format(args.pid_netns)).st_ino

if args.netns_id != 0:
    code = 'if (sk->__sk_common.skc_net.net->ns.inum != {}) {{ return 0; }}'.format(
        args.netns_id)
    bpf_text = bpf_text.replace('FILTER_NETNS', code)
else:
    bpf_text = bpf_text.replace('FILTER_NETNS', '')

# the reasons of skb drop
drop_reasons = {
    0: "SKB_NOT_DROPPED_YET",
    1: "SKB_CONSUMED",
    2: "NOT_SPECIFIED",
    3: "NO_SOCKET",
    4: "SOCKET_CLOSE",
    5: "SOCKET_FILTER",
    6: "SOCKET_RCVBUFF",
    7: "UNIX_DISCONNECT",
    8: "UNIX_SKIP_OOB",
    9: "PKT_TOO_SMALL",
    10: "TCP_CSUM",
    11: "UDP_CSUM",
    12: "NETFILTER_DROP",
    13: "OTHERHOST",
    14: "IP_CSUM",
    15: "IP_INHDR",
    16: "IP_RPFILTER",
    17: "UNICAST_IN_L2_MULTICAST",
    18: "XFRM_POLICY",
    19: "IP_NOPROTO",
    20: "PROTO_MEM",
    21: "TCP_AUTH_HDR",
    22: "TCP_MD5NOTFOUND",
    23: "TCP_MD5UNEXPECTED",
    24: "TCP_MD5FAILURE",
    25: "TCP_AONOTFOUND",
    26: "TCP_AOUNEXPECTED",
    27: "TCP_AOKEYNOTFOUND",
    28: "TCP_AOFAILURE",
    29: "SOCKET_BACKLOG",
    30: "TCP_FLAGS",
    31: "TCP_ABORT_ON_DATA",
    32: "TCP_ZEROWINDOW",
    33: "TCP_OLD_DATA",
    34: "TCP_OVERWINDOW",
    35: "TCP_OFOMERGE",
    36: "TCP_RFC7323_PAWS",
    37: "TCP_RFC7323_PAWS_ACK",
    38: "TCP_OLD_SEQUENCE",
    39: "TCP_INVALID_SEQUENCE",
    40: "TCP_INVALID_ACK_SEQUENCE",
    41: "TCP_RESET",
    42: "TCP_INVALID_SYN",
    43: "TCP_CLOSE",
    44: "TCP_FASTOPEN",
    45: "TCP_OLD_ACK",
    46: "TCP_TOO_OLD_ACK",
    47: "TCP_ACK_UNSENT_DATA",
    48: "TCP_OFO_QUEUE_PRUNE",
    49: "TCP_OFO_DROP",
    50: "IP_OUTNOROUTES",
    51: "BPF_CGROUP_EGRESS",
    52: "IPV6DISABLED",
    53: "NEIGH_CREATEFAIL",
    54: "NEIGH_FAILED",
    55: "NEIGH_QUEUEFULL",
    56: "NEIGH_DEAD",
    57: "TC_EGRESS",
    58: "SECURITY_HOOK",
    59: "QDISC_DROP",
    60: "QDISC_OVERLIMIT",
    61: "QDISC_CONGESTED",
    62: "CAKE_FLOOD",
    63: "FQ_BAND_LIMIT",
    64: "FQ_HORIZON_LIMIT",
    65: "FQ_FLOW_LIMIT",
    66: "CPU_BACKLOG",
    67: "XDP",
    68: "TC_INGRESS",
    69: "UNHANDLED_PROTO",
    70: "SKB_CSUM",
    71: "SKB_GSO_SEG",
    72: "SKB_UCOPY_FAULT",
    73: "DEV_HDR",
    74: "DEV_READY",
    75: "FULL_RING",
    76: "NOMEM",
    77: "HDR_TRUNC",
    78: "TAP_FILTER",
    79: "TAP_TXFILTER",
    80: "ICMP_CSUM",
    81: "INVALID_PROTO",
    82: "IP_INADDRERRORS",
    83: "IP_INNOROUTES",
    84: "IP_LOCAL_SOURCE",
    85: "IP_INVALID_SOURCE",
    86: "IP_LOCALNET",
    87: "IP_INVALID_DEST",
    88: "PKT_TOO_BIG",
    89: "DUP_FRAG",
    90: "FRAG_REASM_TIMEOUT",
    91: "FRAG_TOO_FAR",
    92: "TCP_MINTTL",
    93: "IPV6_BAD_EXTHDR",
    94: "IPV6_NDISC_FRAG",
    95: "IPV6_NDISC_HOP_LIMIT",
    96: "IPV6_NDISC_BAD_CODE",
    97: "IPV6_NDISC_BAD_OPTIONS",
    98: "IPV6_NDISC_NS_OTHERHOST",
    99: "QUEUE_PURGE",
    100: "TC_COOKIE_ERROR",
    101: "PACKET_SOCK_ERROR",
    102: "TC_CHAIN_NOTFOUND",
    103: "TC_RECLASSIFY_LOOP",
    104: "VXLAN_INVALID_HDR",
    105: "VXLAN_VNI_NOT_FOUND",
    106: "MAC_INVALID_SOURCE",
    107: "VXLAN_ENTRY_EXISTS",
    108: "NO_TX_TARGET",
    109: "IP_TUNNEL_ECN",
    110: "TUNNEL_TXINFO",
    111: "LOCAL_MAC",
    112: "ARP_PVLAN_DISABLE",
    113: "MAC_IEEE_MAC_CONTROL",
    114: "BRIDGE_INGRESS_STP_STATE",
}

# process event
def print_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)
    reason_str = drop_reasons.get(event.drop_reason, "UNKNOWN")
    state_flag_str = "%s (%s)" % (tcp.state2str(event.state), tcp.flags2str(event.tcpflags))
    print("%-8s %-7d %-2d %-20s > %-20s %-20s %s (%d)" % (
        strftime("%H:%M:%S"), event.pid, event.ip,
        "%s:%d" % (inet_ntop(AF_INET, pack('I', event.saddr)), event.sport),
        "%s:%s" % (inet_ntop(AF_INET, pack('I', event.daddr)), event.dport),
        state_flag_str, reason_str, event.drop_reason))
    for addr in stack_traces.walk(event.stack_id):
        sym = b.ksym(addr, show_offset=True)
        print("\t%s" % sym)
    print("")

def print_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)
    reason_str = drop_reasons.get(event.drop_reason, "UNKNOWN")
    state_flag_str = "%s (%s)" % (tcp.state2str(event.state), tcp.flags2str(event.tcpflags))
    print("%-8s %-7d %-2d %-20s > %-20s %-20s %s (%d)" % (
        strftime("%H:%M:%S"), event.pid, event.ip,
        "%s:%d" % (inet_ntop(AF_INET6, event.saddr), event.sport),
        "%s:%d" % (inet_ntop(AF_INET6, event.daddr), event.dport),
        state_flag_str, reason_str, event.drop_reason))
    for addr in stack_traces.walk(event.stack_id):
        sym = b.ksym(addr, show_offset=True)
        print("\t%s" % sym)
    print("")

kfree_skb_traceable = False

if BPF.tracepoint_exists("skb", "kfree_skb"):
    if BPF.kernel_struct_has_field("trace_event_raw_kfree_skb", "reason") == 1:
        bpf_text += bpf_kfree_skb_text
        kfree_skb_traceable = True

# initialize BPF
b = BPF(text=bpf_text)

if b.get_kprobe_functions(b"tcp_drop"):
    b.attach_kprobe(event="tcp_drop", fn_name="trace_tcp_drop")
elif b.tracepoint_exists("skb", "kfree_skb") and kfree_skb_traceable:
    print("WARNING: tcp_drop() kernel function not found or traceable. "
          "Use tracepoint:skb:kfree_skb instead.")
else:
    print("ERROR: tcp_drop() kernel function and tracepoint:skb:kfree_skb"
          " not found or traceable. "
          "The kernel might be too old or the the function has been inlined.")
    exit(1)
stack_traces = b.get_table("stack_traces")

# header
print("%-8s %-7s %-2s %-20s > %-20s %-20s %s" % ("TIME", "PID", "IP",
    "SADDR:SPORT", "DADDR:DPORT", "STATE (FLAGS)", "REASON (CODE)"))

# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
b["ipv6_events"].open_perf_buffer(print_ipv6_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

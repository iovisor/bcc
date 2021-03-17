#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# skbstat Trace skb events(input/output/consume/drop) of kernel.
#         For Linux, uses BCC, eBPF. Embedded C.
#
# usage: skbstat.py [-h] [-i INTERVAL] [-s SADDR] [-d DADDR] [-N ADDR]
#                   [-S SPORT] [-D DPORT] [-P PORT] [-p PROTO] [--input]
#                   [--output] [--consume] [--no_drop]
#
# This uses dynamic tracing of kernel functions, and will need to be updated
# to match kernel changes.
#
# Copyright (c) 2021 Dongdong Wang <wangdongdong.6@bytedance.com>
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 10-MAR-2021  Dongdong Wang Created this.

from __future__ import print_function
from bcc import BPF
import sys
import argparse
import ipaddress
from time import strftime
from struct import unpack
from time import sleep

# arguments
examples = """examples:
    skbstat                               # dump kernel skb drop backtraces (default)
    skbstat --no_drop                     # do not dump kernel skb drop backtraces
    skbstat --input                       # dump kernel skb input backtraces
    skbstat --output                      # dump kernel skb output backtraces
    skbstat --consume                     # dump kernel skb consume routines
    skbstat -s 10.0.0.1                   # only trace packet comming from 10.0.0.1
    skbstat -N 10.0.0.1                   # only trace packet comming from or going to 10.0.0.1
    skbstat -N 1000::1                    # only trace packet comming from or going to 1000::1
    skbstat -p tcp                        # only trace TCP packet
    skbstat -p tcp -D 80                  # only trace input HTTP packet
    skbstat -p tcp -P 80                  # only trace input or output HTTP packet
"""
parser = argparse.ArgumentParser(
    description="""
    Trace skb event (input/output/consume/drop) of the kernel.

    WARNING: When run with `--input/output/consume` options, 
    this tool will trace high traffic kernel functions and may lead to 
    some noticeable overhead. Use it carefully on production system.
""",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

parser.add_argument("-i", "--interval", default=3, type=int,
    help="interval in seconds to print backtrace")
parser.add_argument("-s", "--saddr", 
    help="source ip/ipv6 address/network")
parser.add_argument("-d", "--daddr", 
    help="destination ip/ipv6 address/network")
parser.add_argument("-N", "--addr", 
    help="source or destination ip/ipv6 address/network")
parser.add_argument("-S", "--sport", 
    help="source tcp/udp port")
parser.add_argument("-D", "--dport", 
    help="destination tcp/udp port")
parser.add_argument("-P", "--port", 
    help="source or destination tcp/udp port")
parser.add_argument("-p", "--proto", 
    help="protocol ( tcp/udp/icmp ... )")

parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
parser.add_argument("--input", action="store_true",
    help="trace skb input")
parser.add_argument("--output", action="store_true",
    help="trace skb output")
parser.add_argument("--consume", action="store_true",
    help="dump consume_skb backtrace")
parser.add_argument("--no_drop", action="store_true",
    help="don't dump kfree_skb backtrace")

args = parser.parse_args()

# parse args
ip_version = 0
interval = args.interval

def ip_network(addr):
    if sys.version_info[0] < 3:
        return ipaddress.ip_network(unicode(addr))

    return ipaddress.ip_network(addr)

def init_ip_version(cur, new):
    if cur == 0:
        cur = new
    elif cur != new:
        cur = 0

    return cur

def init_addr_filter(addr_str, pos):
    net = ip_network(addr_str)
    addr = net.network_address
    mask = net.netmask

    addr_filter = ""

    if net.version == 4:
        addr_filter += "filter->addr[%d] = 0x%x;\n" % (pos, unpack("=I", addr.packed)[0])
        addr_filter += "\tfilter->mask[%d] = 0x%x;\n" % (pos, unpack("=I", mask.packed)[0])
    elif net.version == 6:
        a0, a1, a2, a3 = unpack("=IIII", addr.packed)
        m0, m1, m2, m3 = unpack("=IIII", mask.packed)

        addr_filter += "filter->addr6[%d][0] = 0x%x;\n" % (pos, a0)
        addr_filter += "\tfilter->addr6[%d][1] = 0x%x;\n" % (pos, a1)
        addr_filter += "\tfilter->addr6[%d][2] = 0x%x;\n" % (pos, a2)
        addr_filter += "\tfilter->addr6[%d][3] = 0x%x;\n" % (pos, a3)

        addr_filter += "\tfilter->mask6[%d][0] = 0x%x;\n" % (pos, m0)
        addr_filter += "\tfilter->mask6[%d][1] = 0x%x;\n" % (pos, m1)
        addr_filter += "\tfilter->mask6[%d][2] = 0x%x;\n" % (pos, m2)
        addr_filter += "\tfilter->mask6[%d][3] = 0x%x;\n" % (pos, m3)

    return addr_filter, net.version

flags_filter = ""

saddr_filter = ""
if args.saddr:
    saddr_filter, ip_version = init_addr_filter(args.saddr, 0)

daddr_filter = ""
if args.daddr:
    daddr_filter, new_version = init_addr_filter(args.daddr, 1)
    ip_version = init_ip_version(ip_version, new_version)

if args.addr:
    flags_filter = "filter->flags |= SKB_ADDR_MATCH_1;\n"
    daddr_filter = ""
    saddr_filter, ip_version = init_addr_filter(args.addr, 0)

ip_version_filter = "filter->ip_version = %d;\n" % ip_version

def check_port(port):
    if port < 0 or port > 65535:
        print("invalid port %d" % port)
        exit()

def check_port_range(port):
    if int(port[0]) > int(port[1]):
        print("invalid port range %d-%d" % (int(port[0]), int(port[1])))
        exit()

def init_port_filter(port_str, name):
    ports = port_str.split('-')
    port = int(ports[0])
    check_port(port)

    port_filter = "filter->%s[0] = htons(%u);\n" % (name, port)

    if len(ports) > 1:
        port = int(ports[1])
        check_port(port)
        check_port_range(ports)

    port_filter += "\tfilter->%s[1] = htons(%u);\n" % (name, port)

    return port_filter

sport_filter = ""
if args.sport:
    sport_filter = init_port_filter(args.sport, "sport_range")

dport_filter = ""
if args.dport:
    dport_filter = init_port_filter(args.dport, "dport_range")

if args.port:
    if flags_filter:
        flags_filter += "\t"
    flags_filter += "filter->flags |= SKB_PORT_MATCH_1;\n"

    dport_filter = ""
    sport_filter = init_port_filter(args.port, "sport_range")

def proto_str2int(proto):
    if proto.lower() == "icmp":
        return 1
    if proto.lower() == "tcp":
        return 6
    if proto.lower() == "udp":
        return 17
    if proto.lower() == "icmp6":
        return 58
    if proto.isdigit():
        proto_num = int(proto)
        if proto_num >= 0 and proto_num <= 255:
            return proto_num
    return 0

proto = 0
proto_filter = ""
if args.proto:
    proto = proto_str2int(args.proto)
    proto_filter += "filter->proto = %d;\n" % proto

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/if_ether.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_TABLE("percpu_hash", u32, u64, drop_stacks, 256);
BPF_TABLE("percpu_hash", u32, u64, consume_stacks, 256);
BPF_TABLE("percpu_hash", u64, u64, input, 256);
BPF_TABLE("percpu_hash", u64, u64, forward, 256);
BPF_TABLE("percpu_hash", u64, u64, output, 256);
BPF_STACK_TRACE(stack_traces, 10240);

union l4hdr {
	struct {
		__be16 src;
		__be16 dst;
	} tcpudphdr;
};

#define SKB_ADDR_MATCH_1    (1UL << 0)
#define SKB_PORT_MATCH_1    (1UL << 1)

struct filter {
	__be32 addr[2], mask[2];
	__be32 addr6[2][4], mask6[2][4];
	__be16 sport_range[2], dport_range[2];
	u16 flags;
	u8 proto;
	u8 ip_version;
};

union filter_args {
	bool drop;
	struct {
		bool input;
		bool output;
		bool forward;
	};
};

static inline int port_range_match(u16 port, u16 * port_range)
{
	return (port_range[0] || port_range[1]) ?
	    (port >= port_range[0] && port <= port_range[1]) : 1;
}

static inline int port_match2(u16 sport, u16 dport, struct filter *filter)
{
	return (sport ? port_range_match(sport, filter->sport_range) : 1) &&
	    (dport ? port_range_match(dport, filter->dport_range) : 1);
}

static inline int port_match1(u16 sport, u16 dport, struct filter *filter)
{
	return port_range_match(sport, filter->sport_range) ||
	    port_range_match(dport, filter->sport_range);
}

static inline int port_match(u16 sport, u16 dport, struct filter *filter)
{
	return (filter->flags & SKB_PORT_MATCH_1) ? 
            port_match1(sport, dport, filter) :
	    port_match2(sport, dport, filter);
}

static inline int proto_match(u8 proto, struct filter *filter)
{
	return (filter->proto && proto) ? filter->proto == proto : 1;
}

static inline int ip6_addr_match2(unsigned __int128 saddr,
				  unsigned __int128 daddr, struct filter *filter)
{
	unsigned __int128 saddr_expect = *((unsigned __int128 *)(filter->addr6[0])), 
            daddr_expect = *((unsigned __int128 *)(filter->addr6[1]));
	unsigned __int128 saddr_mask = *((unsigned __int128 *)(filter->mask6[0])), 
            daddr_mask = *((unsigned __int128 *)(filter->mask6[1]));

	return (saddr_expect ? (saddr & saddr_mask) == saddr_expect : 1)
	    && (daddr_expect ? (daddr & daddr_mask) == daddr_expect : 1);
}

static inline int ip6_addr_match1(unsigned __int128 saddr,
				  unsigned __int128 daddr, struct filter *filter)
{
	unsigned __int128 addr_expect =
	    *((unsigned __int128 *)(filter->addr6[0]));
	unsigned __int128 addr_mask =
	    *((unsigned __int128 *)(filter->mask6[0]));

	return ((saddr & addr_mask) == addr_expect)
	    || ((daddr & addr_mask) == addr_expect);
}

static inline int ip6_addr_match(unsigned __int128 saddr,
				 unsigned __int128 daddr, struct filter *filter)
{
	return (filter->flags & SKB_ADDR_MATCH_1) ? 
            ip6_addr_match1(saddr, daddr, filter) :
	    ip6_addr_match2(saddr, daddr, filter);
}

static inline int ip_addr_match2(__be32 saddr, __be32 daddr, struct filter *filter)
{
	return (filter->addr[0] ? (saddr & filter->mask[0]) ==
		filter->addr[0] : 1)
	    && (filter->addr[1] ? (daddr & filter->mask[1]) ==
		filter->addr[1] : 1);
}

static inline int ip_addr_match1(__be32 saddr, __be32 daddr, struct filter *filter)
{
	return ((saddr & filter->mask[0]) == filter->addr[0])
	    || ((daddr & filter->mask[0]) == filter->addr[0]);
}

static inline int ip_addr_match(__be32 saddr, __be32 daddr, struct filter *filter)
{
	return (filter->flags & SKB_ADDR_MATCH_1) ? 
            ip_addr_match1(saddr, daddr, filter) :
	    ip_addr_match2(saddr, daddr, filter);
}

static inline int record_skb(struct pt_regs *ctx, union filter_args *args)
{
	u64 *count = NULL, zero = 0, ip = PT_REGS_IP(ctx);

	if (args->input) {
		count = input.lookup_or_try_init(&ip, &zero);
	} else if (args->output) {
		count = output.lookup_or_try_init(&ip, &zero);
	} else if (args->forward) {
		count = forward.lookup_or_try_init(&ip, &zero);
	}

	if (count) {
		*count += 1;
	}

	return 0;
}

static inline int record_sk(struct pt_regs *ctx, union filter_args *args)
{
	return record_skb(ctx, args);
}

static inline int record_skb_backtrace(struct pt_regs *ctx,
				       union filter_args *args)
{
	u32 stack_id = stack_traces.get_stackid(ctx, 0);
	u64 *count, zero = 0;

	if (args->drop) {
		count = drop_stacks.lookup_or_try_init(&stack_id, &zero);
	} else {
		count = consume_stacks.lookup_or_try_init(&stack_id, &zero);
	}

	if (count) {
		*count += 1;
	}

	return 0;
}

static inline int skb_l4_match(u8 proto, union l4hdr *hdr,
			       struct filter *filter)
{
	switch (proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		{
			u16 dst = hdr->tcpudphdr.dst, src = hdr->tcpudphdr.src;

			return port_match(src, dst, filter);
		}
	default:
                // TODO: parse other protocols and do some match.
		break;
	}
	return 1;
}

static inline int skb_l4hdr(struct sk_buff *skb, union l4hdr *l4h,
			    int l3_offset)
{
	// transport header was set
	if (skb->transport_header != (typeof(skb->transport_header)) ~ 0U &&
	    skb->transport_header != skb->network_header) {
		if (bpf_probe_read_kernel
		    (l4h, sizeof(union l4hdr),
		     skb->head + skb->transport_header)) {
			goto err;
		}
		goto success;
	}

	if (bpf_probe_read_kernel
	    (l4h, sizeof(union l4hdr),
	     skb->head + skb->network_header + l3_offset)) {
		goto err;
	}

success:
	return 0;
err:
	return -1;
}

static inline int skb_l3hdr(struct sk_buff *skb, void *l3h, int l3h_len)
{
	// network header not set
	if (!skb->network_header) {
		goto err;
	}

	if (bpf_probe_read_kernel
	    (l3h, l3h_len, skb->head + skb->network_header)) {
		goto err;
	}

	return 0;
err:
	return -1;
}

static inline int sk_ip6_match(struct sock *sk, struct filter *filter,
			       union filter_args *args)
{
	unsigned __int128 saddr, daddr;
	u16 sport, dport;

	if (args->input) {
		// see kernel source code include/net/inet6_hashtables.h for detail.
		saddr = *((unsigned __int128 *)(&sk->sk_v6_daddr));
		daddr = *((unsigned __int128 *)(&sk->sk_v6_rcv_saddr));
		sport = sk->sk_dport;
		dport = sk->sk_num;
	} else if (args->output) {
		daddr = *((unsigned __int128 *)(&sk->sk_v6_daddr));
		saddr = *((unsigned __int128 *)(&sk->sk_v6_rcv_saddr));
		dport = sk->sk_dport;
		sport = sk->sk_num;
	} else {
		goto miss;
	}

	if (ip6_addr_match(saddr, daddr, filter)) {
		return port_match(htons(sport), htons(dport), filter);
	}
miss:
	return 0;
}

static inline int skb_ip6_match(struct sk_buff *skb, struct filter *filter)
{
	struct ipv6hdr ip6h;
	union l4hdr l4h;

	if (skb_l3hdr(skb, &ip6h, sizeof(struct ipv6hdr))) {
		goto miss;
	}

	if (!ip6_addr_match
	    (*((unsigned __int128 *)(&ip6h.saddr)),
	     *((unsigned __int128 *)(&ip6h.daddr)), filter)
	    || !proto_match(ip6h.nexthdr, filter)) {
		goto miss;
	}

	if (skb_l4hdr(skb, &l4h, sizeof(struct ipv6hdr))) {
		goto miss;
	}

	return skb_l4_match(ip6h.nexthdr, &l4h, filter);
miss:
	return 0;
}

static inline int sk_ip_match(struct sock *sk, struct filter *filter,
			      union filter_args *args)
{
	u32 saddr, daddr;
	u16 sport, dport;

	if (args->input) {
		// see kernel source code include/net/inet_hashtables.h for detail.
		saddr = sk->sk_daddr;
		daddr = sk->sk_rcv_saddr;
		sport = sk->sk_dport;
		dport = sk->sk_num;
	} else if (args->output) {
		daddr = sk->sk_daddr;
		saddr = sk->sk_rcv_saddr;
		dport = sk->sk_dport;
		sport = sk->sk_num;
	} else {
		goto miss;
	}

	if (ip_addr_match(saddr, daddr, filter)) {
		return port_match(htons(sport), htons(dport), filter);
	}
miss:
	return 0;
}

static inline int skb_ip_match(struct sk_buff *skb, struct filter *filter)
{
	struct iphdr iph;
	union l4hdr l4h;

	if (skb_l3hdr(skb, &iph, sizeof(struct iphdr))) {
		goto miss;
	}

	if (!ip_addr_match(iph.saddr, iph.daddr, filter)
	    || !proto_match(iph.protocol, filter)) {
		goto miss;
	}

	if (skb_l4hdr(skb, &l4h, iph.ihl * 4)) {
		goto miss;
	}

	return skb_l4_match(iph.protocol, &l4h, filter);
miss:
	return 0;
}

static inline int sk_is_ipv6(struct sock *sk)
{
	return sk->sk_family == AF_INET6;
}

static inline int skb_is_ipv6(struct sk_buff *skb)
{
	return skb->protocol && skb->protocol == htons(ETH_P_IPV6);
}

static inline int sk_is_ipv4(struct sock *sk)
{
	return sk->sk_family == AF_INET;
}

static inline int skb_is_ipv4(struct sk_buff *skb)
{
	return skb->protocol && skb->protocol == htons(ETH_P_IP);
}

static inline void filter_init(struct filter *filter)
{
	SADDR_FILTER
	DADDR_FILTER
	SPORT_FILTER
	DPORT_FILTER 
	PROTO_FILTER 
	FLAGS_FILTER 
	IP_VERSION_FILTER
}

static inline int sk_match_and_trace(struct pt_regs *ctx, struct sock *sk,
				     union filter_args *args,
				     int (*cb) (struct pt_regs *,
						union filter_args *))
{
	struct filter filter = { };

	filter_init(&filter);

	if ((filter.ip_version == 0 || filter.ip_version == 4)
	    && sk_is_ipv4(sk)) {
		if (sk_ip_match(sk, &filter, args)) {
			return cb(ctx, args);
		}
	} else if ((filter.ip_version == 0 || filter.ip_version == 6)
		   && sk_is_ipv6(sk)) {
		if (sk_ip6_match(sk, &filter, args)) {
			return cb(ctx, args);
		}
	}

	return 0;
}

static inline int skb_match_and_trace(struct pt_regs *ctx, struct sk_buff *skb,
				      union filter_args *args,
				      int (*cb) (struct pt_regs *,
						 union filter_args *))
{
	struct filter filter = { };

	filter_init(&filter);

	if ((filter.ip_version == 0 || filter.ip_version == 4)
	    && skb_is_ipv4(skb)) {
		if (skb_ip_match(skb, &filter)) {
			return cb(ctx, args);
		}
	} else if ((filter.ip_version == 0 || filter.ip_version == 6)
		   && skb_is_ipv6(skb)) {
		if (skb_ip6_match(skb, &filter)) {
			return cb(ctx, args);
		}
	}

	return 0;
}

static inline int __trace_sk_input(struct pt_regs *ctx, struct sock *sk)
{
	union filter_args args = { };

	args.input = true;

	return sk_match_and_trace(ctx, sk, &args, &record_sk);
}

static inline int __trace_skb_input(struct pt_regs *ctx, struct sk_buff *skb)
{
	union filter_args args = { };

	args.input = true;

	return skb_match_and_trace(ctx, skb, &args, &record_skb);
}

static inline int __trace_sk_output(struct pt_regs *ctx, struct sock *sk)
{
	union filter_args args = { };

	args.output = true;

	return sk_match_and_trace(ctx, sk, &args, &record_sk);
}

static inline int __trace_skb_output(struct pt_regs *ctx, struct sk_buff *skb)
{
	union filter_args args = { };

	args.output = true;

	return skb_match_and_trace(ctx, skb, &args, &record_skb);
}

int trace_sk_input(struct pt_regs *ctx, struct sock *sk)
{
	return __trace_sk_input(ctx, sk);
}

int trace_skb_input_arg3(struct pt_regs *ctx, void *arg1, void *arg2,
			 struct sk_buff *skb)
{
	return __trace_skb_input(ctx, skb);
}

int trace_skb_input(struct pt_regs *ctx, struct sk_buff *skb)
{
	return __trace_skb_input(ctx, skb);
}

int trace_sk_output(struct pt_regs *ctx, struct sock *sk)
{
	return __trace_sk_output(ctx, sk);
}

int trace_skb_output_arg3(struct pt_regs *ctx, void *arg1, void *arg2,
			  struct sk_buff *skb)
{
	return __trace_skb_output(ctx, skb);
}

int trace_skb_output(struct pt_regs *ctx, struct sk_buff *skb)
{
	return __trace_skb_output(ctx, skb);
}

int trace_skb_forward(struct pt_regs *ctx, struct sk_buff *skb)
{
	union filter_args args = { };

	args.forward = true;

	return skb_match_and_trace(ctx, skb, &args, &record_skb);
}

int trace_skb_drop(struct pt_regs *ctx, struct sk_buff *skb)
{
	union filter_args args = { };

	args.drop = true;

	return skb_match_and_trace(ctx, skb, &args, &record_skb_backtrace);
}

int trace_skb_consume(struct pt_regs *ctx, struct sk_buff *skb)
{
	union filter_args args = { };

	return skb_match_and_trace(ctx, skb, &args, &record_skb_backtrace);
}

int trace_net_dev_xmit(struct tracepoint__net__net_dev_xmit *args)
{
        struct pt_regs ctx = {};
        struct sk_buff *skb = (struct sk_buff *)args->skbaddr;

        PT_REGS_IP(&ctx) = net:net_dev_xmit;

        return __trace_skb_output(&ctx, skb);
}

int trace_net_dev_queue(struct tracepoint__net__net_dev_queue *args)
{
        struct pt_regs ctx = {};
        struct sk_buff *skb = (struct sk_buff *)args->skbaddr;

        PT_REGS_IP(&ctx) = net:net_dev_queue;

        return __trace_skb_output(&ctx, skb);
}

int trace_netif_receive_skb(struct tracepoint__net__netif_receive_skb *args)
{
        struct pt_regs ctx = {};
        struct sk_buff *skb = (struct sk_buff *)args->skbaddr;

        PT_REGS_IP(&ctx) = net:netif_receive_skb;

        return __trace_skb_input(&ctx, skb);
}
"""

# internal address for tracepoint.
tracepoint_addr2func = {
    1: "net:netif_receive_skb",
    2: "net:net_dev_queue",
    3: "net:net_dev_xmit",
}

# apply filters
bpf_text = bpf_text.replace('SADDR_FILTER', saddr_filter)
bpf_text = bpf_text.replace('DADDR_FILTER', daddr_filter)
bpf_text = bpf_text.replace('SPORT_FILTER', sport_filter)
bpf_text = bpf_text.replace('DPORT_FILTER', dport_filter)
bpf_text = bpf_text.replace('PROTO_FILTER', proto_filter)
bpf_text = bpf_text.replace('FLAGS_FILTER', flags_filter)
bpf_text = bpf_text.replace('IP_VERSION_FILTER', ip_version_filter)

# replace tracepoint address.
for addr, tp in tracepoint_addr2func.items():
    bpf_text = bpf_text.replace(tp, str(addr))

# dump ebpf and exit
if args.ebpf:
    print(bpf_text)
    exit()

# initialize BPF
b = BPF(text=bpf_text)

# PROBE LIST
# the dict key is function to probe, value is tuple.
# the first entry of tuple is probe function, the second
# one is the output priority, which can be used by sorter()
# function. the name of probe function with biggest output 
# priority number sits at last of output lines.

# NOTE: those kernel functions may be inlined by compiler
# or just not exists in some kernel versions. so it may 
# lead to some potential issues. If you find it, please 
# report to us.

probe_list_input_dev = {
    "net:netif_receive_skb": ("trace_netif_receive_skb", 30),
}

probe_list_input_ip = {
    "ip_error": ("trace_skb_input", 19),
    "ip_rcv": ("trace_skb_input", 19),
    "ip_rcv_finish": ("trace_skb_input_arg3", 18),
    "ip_route_input_noref": ("trace_skb_input", 17),
    "ip_local_deliver": ("trace_skb_input", 16),
    "ip_local_deliver_finish": ("trace_skb_input_arg3", 15),
}

probe_list_input_ip6 = {
    "ip6_pkt_drop": ("trace_skb_input", 19),
    "ipv6_rcv": ("trace_skb_input", 19),
    "ip6_rcv_finish": ("trace_skb_input_arg3", 18),
    "ip6_route_input": ("trace_skb_input", 17),
    "ip6_input": ("trace_skb_input", 16),
    "ip6_input_finish": ("trace_skb_input_arg3", 15),
}

probe_list_input_icmp = {
    "icmp_rcv": ("trace_skb_input", 2),
}

probe_list_input_icmp6 = {
    "icmpv6_rcv": ("trace_skb_input", 2),
}

probe_list_input_tcp4 = {
    "tcp_v4_rcv": ("trace_skb_input", 2),
}

probe_list_input_tcp6 = {
    "tcp_v6_rcv": ("trace_skb_input", 2),
}

probe_list_input_udp4 = {
    "udp_rcv": ("trace_skb_input", 2),
}

probe_list_input_udp6 = {
    "udpv6_rcv": ("trace_skb_input", 2),
}

probe_list_input_tcp = {
    "tcp_drop": ("trace_sk_input", 1),
    "tcp_recvmsg": ("trace_sk_input", 0),
}

probe_list_input_udp = {
    "udp_recvmsg": ("trace_sk_input", 0),
}

probe_list_input = [
    probe_list_input_dev,
    probe_list_input_ip,
    probe_list_input_ip6,
    probe_list_input_icmp,
    probe_list_input_icmp6,
    probe_list_input_tcp4,
    probe_list_input_tcp6,
    probe_list_input_udp4,
    probe_list_input_udp6,
    probe_list_input_tcp,
    probe_list_input_udp,
]

probe_list_output_tcp = {
    "tcp_sendmsg": ("trace_sk_output", 0),
}

probe_list_output_udp = {
    "udp_sendmsg": ("trace_sk_output", 0),
}

probe_list_output_ip = {
    "ip_local_out": ("trace_skb_output", 10),
    "ip_output": ("trace_skb_output_arg3", 11),
    "ip_finish_output": ("trace_skb_output_arg3", 12),
    "ip_finish_output2": ("trace_skb_output_arg3", 13),
}

probe_list_output_ip6 = {
    "__ip6_local_out": ("trace_skb_output_arg3", 10),
    "ip6_output": ("trace_skb_output_arg3", 11),
    "ip6_finish_output": ("trace_skb_output_arg3", 12),
    "ip6_finish_output2": ("trace_skb_output_arg3", 13),
}

probe_list_output_dev = {
    "net:net_dev_queue": ("trace_net_dev_queue", 20),
    "net:net_dev_xmit": ("trace_net_dev_xmit", 21),
}

probe_list_output = [
    probe_list_output_dev,
    probe_list_output_ip,
    probe_list_output_ip6,
    probe_list_output_tcp,
    probe_list_output_udp,
]

def try_probe(b, e, fn):
    if e.find(":") != -1:
        # tracepoint
        events = b.get_tracepoints(str.encode("^" + e + "$"))
        if len(events) == 0:
            print("ERROR: %s() kernel tracepoint not found. " % e)
            return

        b.attach_tracepoint(tp=e, fn_name=fn)
    else:
        # kprobe
        events = b.get_kprobe_functions(str.encode("^" + e + "$"))
        if len(events) == 0:
            print("ERROR: %s() kernel function not found or traceable. "
                "The function may have been inlined by compiler or just not exists." % e)
            return

        b.attach_kprobe(event=e, fn_name=fn)

def try_probe_list(b, l):
    for k, v in l.items():
        try_probe(b, k, v[0])

def try_probe_dev_input(b):
    try_probe_list(b, probe_list_input_dev)

def try_probe_dev_output(b):
    try_probe_list(b, probe_list_output_dev)

def try_probe_network_input(b, ip_version):
    if ip_version == 0 or ip_version == 4:
        try_probe_list(b, probe_list_input_ip)
    if ip_version == 0 or ip_version == 6:
        try_probe_list(b, probe_list_input_ip6)

def try_probe_network_output(b, ip_version):
    if ip_version == 0 or ip_version == 4:
        try_probe_list(b, probe_list_output_ip)

    if ip_version == 0 or ip_version == 6:
        try_probe_list(b, probe_list_output_ip6)

def try_probe_transport_input(b, ip_version, proto):
    if ip_version == 0 or ip_version == 4:
        if proto == 0 or proto == 6:
            try_probe_list(b, probe_list_input_tcp4)

        if proto == 0 or proto == 17:
            try_probe_list(b, probe_list_input_udp4)

        if proto == 0 or proto == 1:
            try_probe_list(b, probe_list_input_icmp)

    if ip_version == 0 or ip_version == 6:
        if proto == 0 or proto == 6:
            try_probe_list(b, probe_list_input_tcp6)

        if proto == 0 or proto == 17:
            try_probe_list(b, probe_list_input_udp6)

        if proto == 0 or proto == 58:
            try_probe_list(b, probe_list_input_icmp6)

    if proto == 0 or proto == 6:
        try_probe_list(b, probe_list_input_tcp)

    if proto == 0 or proto == 17:
        try_probe_list(b, probe_list_input_udp)

def try_probe_transport_output(b, ip_version, proto):
    if proto == 0 or proto == 6:
        try_probe_list(b, probe_list_output_tcp)

    if proto == 0 or proto == 17:
        try_probe_list(b, probe_list_output_udp)

def try_probe_drop(b):
    try_probe(b, "kfree_skb", "trace_skb_drop")

def try_probe_consume(b):
    try_probe(b, "consume_skb", "trace_skb_consume")

# install probes
try_probe_drop(b)

if args.input:
    try_probe_dev_input(b)
    try_probe_network_input(b, ip_version)
    try_probe_transport_input(b, ip_version, proto)

if args.output:
    try_probe_dev_output(b)
    try_probe_network_output(b, ip_version)
    try_probe_transport_output(b, ip_version, proto)

if args.consume:
    try_probe_consume(b)

# get maps
input_map = b.get_table("input")
output_map = b.get_table("output")

stack_traces = b.get_table("stack_traces")
drop_stacks = b.get_table("drop_stacks")
consume_stacks = b.get_table("consume_stacks")

def sorter(item, probe_list):
    name = item[0]

    for p in probe_list:
        if name in p:
            return p[name][1]

    return 0xffffffff

def input_sorter(item):
    return sorter(item, probe_list_input)

def output_sorter(item):
    return sorter(item, probe_list_output)

def print_routines(b, maps, sorter):
    funcs = []
    for addr, count in maps.items():
        func_name = ""
        if addr.value in tracepoint_addr2func:
            func_name = tracepoint_addr2func[addr.value]
        else:
            func_name = b.ksym(addr)

        funcs.append([func_name, sum(count), ""])
    for item in sorted(funcs, key=sorter):
        print("%-8s %-6d %s" %(" ", item[1], item[0]))

def print_routines_header(direction):
    print("\n%-8s %-6s %s" % ("TIME", "NUM", "FUNC/STACK"))
    print("%-8s %-6s [%s]" % (strftime("%H:%M:%S"), " ", direction))

def print_input_routines():
    print_routines_header("INGRESS")
    print_routines(b, input_map, input_sorter)
    input_map.clear()

def print_output_routines():
    print_routines_header("EGRESS")
    print_routines(b, output_map, output_sorter)
    output_map.clear()

def print_backtraces(b, stacks, stack_traces):
    for stack_id, count in sorted(stacks.items(), 
            key=lambda kv: sum(kv[1])):
        print("%-8s %-6d" %(" ", sum(count)))
        try:
            for addr in stack_traces.walk(stack_id.value):
                sym = b.ksym(addr, show_offset=True)
                print("%-8s %-6s %s" % (" ", " ", sym))
        except KeyError:
                print("%-8s %-6s [lost kernel stack id %d]" %(" ", " ", stack_id.value))

def print_drop_backtraces():
    print_routines_header("DROP")
    print_backtraces(b, drop_stacks, stack_traces)
    drop_stacks.clear()

def print_consume_backtraces():
    print_routines_header("CONSUME")
    print_backtraces(b, consume_stacks, stack_traces)
    consume_stacks.clear()

# read events
while 1:
    try:
        sleep(interval)

        if args.input:
            print_input_routines()

        if args.output:
            print_output_routines()

        if args.consume:
            print_consume_backtraces()

        if not args.no_drop:
            print_drop_backtraces()

        stack_traces.clear()

    except KeyboardInterrupt:
        exit()

#!/usr/bin/env python
#
# tc_perf_event.py  Output skb and meta data through perf event
#
# Copyright (c) 2016-present, Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import ctypes as ct
import pyroute2
import socket

bpf_txt = """
#include <uapi/linux/if_ether.h>
#include <uapi/linux/in6.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/bpf.h>

BPF_PERF_OUTPUT(skb_events);

struct eth_hdr {
	unsigned char   h_dest[ETH_ALEN];
	unsigned char   h_source[ETH_ALEN];
	unsigned short  h_proto;
};

int handle_egress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct eth_hdr *eth = data;
	struct ipv6hdr *ip6h = data + sizeof(*eth);
	u32 magic = 0xfaceb00c;

	/* single length check */
	if (data + sizeof(*eth) + sizeof(*ip6h) > data_end)
		return TC_ACT_OK;

	if (eth->h_proto == htons(ETH_P_IPV6) &&
	    ip6h->nexthdr == IPPROTO_ICMPV6)
	        skb_events.perf_submit_skb(skb, skb->len, &magic, sizeof(magic));

	return TC_ACT_OK;
}"""

def print_skb_event(cpu, data, size):
    class SkbEvent(ct.Structure):
        _fields_ =  [ ("magic", ct.c_uint32),
                      ("raw", ct.c_ubyte * (size - ct.sizeof(ct.c_uint32))) ]

    skb_event = ct.cast(data, ct.POINTER(SkbEvent)).contents
    icmp_type = int(skb_event.raw[54])

    # Only print for echo request
    if icmp_type == 128:
        src_ip = bytes(bytearray(skb_event.raw[22:38]))
        dst_ip = bytes(bytearray(skb_event.raw[38:54]))
        print("%-3s %-32s %-12s 0x%08x" %
              (cpu, socket.inet_ntop(socket.AF_INET6, src_ip),
               socket.inet_ntop(socket.AF_INET6, dst_ip),
               skb_event.magic))

try:
    b = BPF(text=bpf_txt)
    fn = b.load_func("handle_egress", BPF.SCHED_CLS)

    ipr = pyroute2.IPRoute()
    ipr.link("add", ifname="me", kind="veth", peer="you")
    me = ipr.link_lookup(ifname="me")[0]
    you = ipr.link_lookup(ifname="you")[0]
    for idx in (me, you):
        ipr.link('set', index=idx, state='up')

    ipr.tc("add", "clsact", me)
    ipr.tc("add-filter", "bpf", me, ":1", fd=fn.fd, name=fn.name,
           parent="ffff:fff3", classid=1, direct_action=True)

    b["skb_events"].open_perf_buffer(print_skb_event)
    print('Try: "ping6 ff02::1%me"\n')
    print("%-3s %-32s %-12s %-10s" % ("CPU", "SRC IP", "DST IP", "Magic"))
    while True:
        b.perf_buffer_poll()
finally:
    if "me" in locals(): ipr.link("del", index=me)

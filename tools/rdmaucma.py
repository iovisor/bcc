#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# rdmaucma: Trace RDMA Userspace Connection Manager Access Event.
#           For Linux, uses BCC, eBPF.
#
# USAGE: rdmaucma [-h]
#
# Copyright (c) 2023 zhenwei pi
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 29-MAY-2023  zhenwei pi  Created this.

from __future__ import print_function
from bcc import BPF
from socket import inet_ntop, AF_INET, AF_INET6
import socket, struct
import argparse
import ctypes
from time import strftime

# arguments
examples = """examples:
    ./rdmaucma            # Trace all RDMA Userspace Connection Manager Access Event
"""
parser = argparse.ArgumentParser(
    description="Trace RDMA Userspace Connection Manager Access Event",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-D", "--debug", action="store_true",
    help="print BPF program before starting (for debugging purposes)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

# define BPF program
bpf_text = """
#include <linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include <rdma/rdma_cm.h>

struct ipv4_data_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    int event;
};

BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 sport;
    u16 dport;
    int event;
};

BPF_PERF_OUTPUT(ipv6_events);

int trace_ucma_event_handler(struct pt_regs *ctx,
                             struct rdma_cm_id *cm_id,
                             struct rdma_cm_event *event)
{
    struct sockaddr_storage *ss = &cm_id->route.addr.src_addr;

    if (ss->ss_family == AF_INET) {
        struct ipv4_data_t ipv4_data = { 0 };
        struct sockaddr_in *addr4 = (struct sockaddr_in *)ss;
        ipv4_data.sport = addr4->sin_port;
        ipv4_data.saddr = addr4->sin_addr.s_addr;

        addr4 = (struct sockaddr_in *)&cm_id->route.addr.dst_addr;
        ipv4_data.dport = addr4->sin_port;
        ipv4_data.daddr = addr4->sin_addr.s_addr;

        ipv4_data.event = event->event;
        ipv4_events.perf_submit(ctx, &ipv4_data, sizeof(ipv4_data));
    } else if (ss->ss_family == AF_INET6) {
        struct ipv6_data_t ipv6_data = { 0 };
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)ss;
        ipv6_data.sport = addr6->sin6_port;
        bpf_probe_read_kernel(&ipv6_data.saddr, sizeof(ipv6_data.saddr), addr6->sin6_addr.in6_u.u6_addr32);

        addr6 = (struct sockaddr_in6 *)&cm_id->route.addr.dst_addr;
        ipv6_data.dport = addr6->sin6_port;
        bpf_probe_read_kernel(&ipv6_data.daddr, sizeof(ipv6_data.daddr), addr6->sin6_addr.in6_u.u6_addr32);

        ipv6_data.event = event->event;
        ipv6_events.perf_submit(ctx, &ipv6_data, sizeof(ipv6_data));
    } else {
        return -EPROTONOSUPPORT;
    }

    return 0;
}
"""

# debug/dump ebpf enable or not
if args.debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# load BPF program
b = BPF(text=bpf_text)
b.attach_kprobe(event="ucma_event_handler", fn_name="trace_ucma_event_handler")

# see linux/include/rdma/rdma_cm.h
rdma_cm_event = [
        "address resolved",
        "address error",
        "route resolved ",
        "route error",
        "connect request",
        "connect response",
        "connect error",
        "unreachable",
        "rejected",
        "established",
        "disconnected",
        "device removal",
        "multicast join",
        "multicast error",
        "address change",
        "timewait exit" ]

def print_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)

    cm_event = "unknown event"
    if event.event < len(rdma_cm_event):
        cm_event = rdma_cm_event[event.event]

    print("%-9s %-16s %-6s %-45s %-45s" % (strftime("%H:%M:%S").encode('ascii'),
        cm_event, "IPv4",
        inet_ntop(AF_INET, struct.pack("I", event.saddr)) + ":" + str(socket.ntohs(event.sport)),
        inet_ntop(AF_INET, struct.pack("I", event.daddr)) + ":" + str(socket.ntohs(event.dport))))

def print_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)

    cm_event = "unknown event"
    if event.event < len(rdma_cm_event):
        cm_event = rdma_cm_event[event.event]

    print("%-9s %-16s %-6s %-45s %-45s" % (strftime("%H:%M:%S").encode('ascii'),
        cm_event, "IPv6",
        inet_ntop(AF_INET6, event.saddr) + ":" + str(socket.ntohs(event.sport)),
        inet_ntop(AF_INET6, event.daddr) + ":" + str(socket.ntohs(event.dport))))


b["ipv4_events"].open_perf_buffer(print_ipv4_event)
b["ipv6_events"].open_perf_buffer(print_ipv6_event)

# output
print("Tracing RDMA Userspace Connection Manager Access event... Hit Ctrl-C to end.")

# address length 39 = max("2001:0db8:3c4d:0015:0000:0000:1a2f:1a2b", "255.255.255.255")
print("%-9s %-16s %-4s %-45s %-45s" % ("Timestamp", "Event", "Family", "Local", "Remote"))

while (1):
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

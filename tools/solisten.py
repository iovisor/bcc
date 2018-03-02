#!/usr/bin/env python
#
# solisten      Trace TCP listen events
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: solisten.py [-h] [-p PID] [--show-netns]
#
# This is provided as a basic example of TCP connection & socket tracing.
# It could be useful in scenarios where load balancers needs to be updated
# dynamically as application is fully initialized.
#
# All IPv4 listen attempts are traced, even if they ultimately fail or the
# the listening program is not willing to accept().
#
# Copyright (c) 2016 Jean-Tiare Le Bigot.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 04-Mar-2016	Jean-Tiare Le Bigot	Created this.

import os
from socket import inet_ntop, AF_INET, AF_INET6, SOCK_STREAM, SOCK_DGRAM
from struct import pack
import argparse
from bcc import BPF
import ctypes as ct

# Arguments
examples = """Examples:
    ./solisten.py              # Stream socket listen
    ./solisten.py -p 1234      # Stream socket listen for specified PID only
    ./solisten.py --netns 4242 # " for the specified network namespace ID only
    ./solisten.py --show-netns # Show network ns ID (useful for containers)
"""

parser = argparse.ArgumentParser(
    description="Stream sockets listen",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("--show-netns", action="store_true",
    help="show network namespace")
parser.add_argument("-p", "--pid", default=0, type=int,
    help="trace this PID only")
parser.add_argument("-n", "--netns", default=0, type=int,
    help="trace this Network Namespace only")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)


# BPF Program
bpf_text = """
#include <net/net_namespace.h>
#include <bcc/proto.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wenum-conversion"
#include <net/inet_sock.h>
#pragma clang diagnostic pop

// Common structure for UDP/TCP IPv4/IPv6
struct listen_evt_t {
    u64 ts_us;
    u64 pid_tgid;
    u64 backlog;
    u64 netns;
    u64 proto;    // familiy << 16 | type
    u64 lport;    // use only 16 bits
    u64 laddr[2]; // IPv4: store in laddr[0]
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(listen_evt);

// Send an event for each IPv4 listen with PID, bound address and port
int kprobe__inet_listen(struct pt_regs *ctx, struct socket *sock, int backlog)
{
        // cast types. Intermediate cast not needed, kept for readability
        struct sock *sk = sock->sk;
        struct inet_sock *inet = (struct inet_sock *)sk;

        // Built event for userland
        struct listen_evt_t evt = {
            .ts_us = bpf_ktime_get_ns() / 1000,
            .backlog = backlog,
        };

        // Get process comm. Needs LLVM >= 3.7.1
        // see https://github.com/iovisor/bcc/issues/393
        bpf_get_current_comm(evt.task, TASK_COMM_LEN);

        // Get socket IP family
        u16 family = sk->__sk_common.skc_family;
        evt.proto = family << 16 | SOCK_STREAM;

        // Get PID
        evt.pid_tgid = bpf_get_current_pid_tgid();

        ##FILTER_PID##

        // Get port
        evt.lport = inet->inet_sport;
        evt.lport = ntohs(evt.lport);

        // Get network namespace id, if kernel supports it
#ifdef CONFIG_NET_NS
        evt.netns = sk->__sk_common.skc_net.net->ns.inum;
#else
        evt.netns = 0;
#endif

        ##FILTER_NETNS##

        // Get IP
        if (family == AF_INET) {
            evt.laddr[0] = inet->inet_rcv_saddr;
        } else if (family == AF_INET6) {
            bpf_probe_read(evt.laddr, sizeof(evt.laddr),
                           sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        }

        // Send event to userland
        listen_evt.perf_submit(ctx, &evt, sizeof(evt));

        return 0;
};
"""

# event data
TASK_COMM_LEN = 16      # linux/sched.h
class ListenEvt(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("pid_tgid", ct.c_ulonglong),
        ("backlog", ct.c_ulonglong),
        ("netns", ct.c_ulonglong),
        ("proto", ct.c_ulonglong),
        ("lport", ct.c_ulonglong),
        ("laddr", ct.c_ulonglong * 2),
        ("task", ct.c_char * TASK_COMM_LEN)
    ]

    # TODO: properties to unpack protocol / ip / pid / tgid ...

# Format output
def event_printer(show_netns):
    def print_event(cpu, data, size):
        # Decode event
        event = ct.cast(data, ct.POINTER(ListenEvt)).contents

        pid = event.pid_tgid & 0xffffffff
        proto_family = event.proto & 0xff
        proto_type = event.proto >> 16 & 0xff

        if proto_family == SOCK_STREAM:
            protocol = "TCP"
        elif proto_family == SOCK_DGRAM:
            protocol = "UDP"
        else:
            protocol = "UNK"

        address = ""
        if proto_type == AF_INET:
            protocol += "v4"
            address = inet_ntop(AF_INET, pack("I", event.laddr[0]))
        elif proto_type == AF_INET6:
            address = inet_ntop(AF_INET6, event.laddr)
            protocol += "v6"

        # Display
        if show_netns:
            print("%-6d %-12.12s %-12s %-6s %-8s %-5s %-39s" % (
                pid, event.task, event.netns, protocol, event.backlog,
                event.lport, address,
            ))
        else:
            print("%-6d %-12.12s %-6s %-8s %-5s %-39s" % (
                pid, event.task, protocol, event.backlog,
                event.lport, address,
            ))

    return print_event

if __name__ == "__main__":
    # Parse arguments
    args = parser.parse_args()

    pid_filter = ""
    netns_filter = ""

    if args.pid:
        pid_filter = "if (evt.pid_tgid != %d) return 0;" % args.pid
    if args.netns:
        netns_filter = "if (evt.netns != %d) return 0;" % args.netns

    bpf_text = bpf_text.replace("##FILTER_PID##", pid_filter)
    bpf_text = bpf_text.replace("##FILTER_NETNS##", netns_filter)

    if args.ebpf:
        print(bpf_text)
        exit()

    # Initialize BPF
    b = BPF(text=bpf_text)
    b["listen_evt"].open_perf_buffer(event_printer(args.show_netns))

    # Print headers
    if args.show_netns:
        print("%-6s %-12s %-12s %-6s %-8s %-5s %-39s" %
              ("PID", "COMM", "NETNS", "PROTO", "BACKLOG", "PORT", "ADDR"))
    else:
        print("%-6s %-12s %-6s %-8s %-5s %-39s" %
              ("PID", "COMM", "PROTO", "BACKLOG", "PORT", "ADDR"))

    # Read events
    while 1:
        b.perf_buffer_poll()

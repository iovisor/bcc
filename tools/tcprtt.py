#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# tcprtt    Summarize TCP RTT as a histogram. For Linux, uses BCC, eBPF.
#
# USAGE: tcprtt [-h] [-T] [-D] [-m] [-i INTERVAL] [-d DURATION]
#           [-p LPORT] [-P RPORT] [-a LADDR] [-A RADDR] [-b] [-B] [-e]
#           [-4 | -6]
#
# Copyright (c) 2020 zhenwei pi
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 23-AUG-2020  zhenwei pi  Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
from socket import inet_ntop, inet_pton, AF_INET, AF_INET6
import socket, struct
import argparse
import ctypes

# arguments
examples = """examples:
    ./tcprtt            # summarize TCP RTT
    ./tcprtt -i 1 -d 10 # print 1 second summaries, 10 times
    ./tcprtt -m -T      # summarize in millisecond, and timestamps
    ./tcprtt -p         # filter for local port
    ./tcprtt -P         # filter for remote port
    ./tcprtt -a         # filter for local address
    ./tcprtt -A         # filter for remote address
    ./tcprtt -b         # show sockets histogram by local address
    ./tcprtt -B         # show sockets histogram by remote address
    ./tcprtt -D         # show debug bpf text
    ./tcprtt -e         # show extension summary(average)
    ./tcprtt -4         # trace only IPv4 family
    ./tcprtt -6         # trace only IPv6 family
"""
parser = argparse.ArgumentParser(
    description="Summarize TCP RTT as a histogram",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-i", "--interval",
    help="summary interval, seconds")
parser.add_argument("-d", "--duration", type=int, default=99999,
    help="total duration of trace, seconds")
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="millisecond histogram")
parser.add_argument("-p", "--lport",
    help="filter for local port")
parser.add_argument("-P", "--rport",
    help="filter for remote port")
parser.add_argument("-a", "--laddr",
    help="filter for local address")
parser.add_argument("-A", "--raddr",
    help="filter for remote address")
parser.add_argument("-b", "--byladdr", action="store_true",
    help="show sockets histogram by local address")
parser.add_argument("-B", "--byraddr", action="store_true",
    help="show sockets histogram by remote address")
parser.add_argument("-e", "--extension", action="store_true",
    help="show extension summary(average)")
parser.add_argument("-D", "--debug", action="store_true",
    help="print BPF program before starting (for debugging purposes)")
group = parser.add_mutually_exclusive_group()
group.add_argument("-4", "--ipv4", action="store_true",
    help="trace IPv4 family only")
group.add_argument("-6", "--ipv6", action="store_true",
    help="trace IPv6 family only")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
if not args.interval:
    args.interval = args.duration

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>

typedef struct sock_key {
    u64 addr;
    u64 slot;
} sock_key_t;

typedef struct sock_latenty {
    u64 latency;
    u64 count;
} sock_latency_t;

BPF_HISTOGRAM(hist_srtt, sock_key_t);
BPF_HASH(latency, u64, sock_latency_t);

int trace_tcp_rcv(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb)
{
    struct tcp_sock *ts = (struct tcp_sock *)sk;
    u32 srtt = ts->srtt_us >> 3;
    const struct inet_sock *inet = (struct inet_sock *)sk;

    /* filters */
    u16 sport = 0;
    u16 dport = 0;
    u32 saddr = 0;
    u32 daddr = 0;
    __u8 saddr6[16];
    __u8 daddr6[16];
    u16 family = 0;

    /* for histogram */
    sock_key_t key;

    /* for avg latency, if no saddr/daddr specified, use 0(addr) as key */
    u64 addr = 0;

    bpf_probe_read_kernel(&sport, sizeof(sport), (void *)&inet->inet_sport);
    bpf_probe_read_kernel(&dport, sizeof(dport), (void *)&inet->inet_dport);
    bpf_probe_read_kernel(&family, sizeof(family), (void *)&sk->__sk_common.skc_family);
    if (family == AF_INET6) {
        bpf_probe_read_kernel(&saddr6, sizeof(saddr6),
                              (void *)&sk->__sk_common.skc_v6_rcv_saddr.s6_addr);
        bpf_probe_read_kernel(&daddr6, sizeof(daddr6),
                              (void *)&sk->__sk_common.skc_v6_daddr.s6_addr);
    } else {
        bpf_probe_read_kernel(&saddr, sizeof(saddr), (void *)&inet->inet_saddr);
        bpf_probe_read_kernel(&daddr, sizeof(daddr), (void *)&inet->inet_daddr);
    }

    LPORTFILTER
    RPORTFILTER
    LADDRFILTER
    RADDRFILTER
    FAMILYFILTER

    FACTOR

    STORE_HIST
    key.slot = bpf_log2l(srtt);
    hist_srtt.atomic_increment(key);

    STORE_LATENCY

    return 0;
}
"""

# filter for local port
if args.lport:
    bpf_text = bpf_text.replace('LPORTFILTER',
        """if (ntohs(sport) != %d)
        return 0;""" % int(args.lport))
else:
    bpf_text = bpf_text.replace('LPORTFILTER', '')

# filter for remote port
if args.rport:
    bpf_text = bpf_text.replace('RPORTFILTER',
        """if (ntohs(dport) != %d)
        return 0;""" % int(args.rport))
else:
    bpf_text = bpf_text.replace('RPORTFILTER', '')

def addrfilter(addr, src_or_dest):
    try:
        naddr = socket.inet_pton(AF_INET, addr)
    except:
        naddr = socket.inet_pton(AF_INET6, addr)
        s = ('\\' + struct.unpack("=16s", naddr)[0].hex('\\')).replace('\\', '\\x')
        filter = "if (memcmp(%s6, \"%s\", 16)) return 0;" % (src_or_dest, s)
    else:
        filter = "if (%s != %d) return 0;" % (src_or_dest, struct.unpack("=I", naddr)[0])
    return filter

# filter for local address
if args.laddr:
    bpf_text = bpf_text.replace('LADDRFILTER', addrfilter(args.laddr, 'saddr'))
else:
    bpf_text = bpf_text.replace('LADDRFILTER', '')

# filter for remote address
if args.raddr:
    bpf_text = bpf_text.replace('RADDRFILTER', addrfilter(args.raddr, 'daddr'))
else:
    bpf_text = bpf_text.replace('RADDRFILTER', '')
if args.ipv4:
    bpf_text = bpf_text.replace('FAMILYFILTER',
        'if (family != AF_INET) { return 0; }')
elif args.ipv6:
    bpf_text = bpf_text.replace('FAMILYFILTER',
        'if (family != AF_INET6) { return 0; }')
else:
    bpf_text = bpf_text.replace('FAMILYFILTER', '')
# show msecs or usecs[default]
if args.milliseconds:
    bpf_text = bpf_text.replace('FACTOR', 'srtt /= 1000;')
    label = "msecs"
else:
    bpf_text = bpf_text.replace('FACTOR', '')
    label = "usecs"

print_header = "srtt"
# show byladdr/byraddr histogram
if args.byladdr:
    bpf_text = bpf_text.replace('STORE_HIST', 'key.addr = addr = saddr;')
    print_header = "Local Address"
elif args.byraddr:
    bpf_text = bpf_text.replace('STORE_HIST', 'key.addr = addr = daddr;')
    print_header = "Remote Addres"
else:
    bpf_text = bpf_text.replace('STORE_HIST', 'key.addr = addr = 0;')
    print_header = "All Addresses"

if args.extension:
    bpf_text = bpf_text.replace('STORE_LATENCY', """
    sock_latency_t newlat = {0};
    sock_latency_t *lat;
    lat = latency.lookup(&addr);
    if (!lat) {
        newlat.latency += srtt;
        newlat.count += 1;
        latency.update(&addr, &newlat);
    } else {
        lat->latency +=srtt;
        lat->count += 1;
    }
    """)
else:
    bpf_text = bpf_text.replace('STORE_LATENCY', '')

# debug/dump ebpf enable or not
if args.debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# check whether hash table batch ops is supported
htab_batch_ops = True if BPF.kernel_struct_has_field(b'bpf_map_ops',
        b'map_lookup_and_delete_batch') == 1 else False

# load BPF program
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_rcv_established", fn_name="trace_tcp_rcv")

print("Tracing TCP RTT... Hit Ctrl-C to end.")

def print_section(addr):
    addrstr = "*******"
    if (addr):
        addrstr = inet_ntop(AF_INET, struct.pack("I", addr))

    avglat = ""
    if args.extension:
        lats = b.get_table("latency")
        lat = lats[ctypes.c_ulong(addr)]
        avglat = " [AVG %d]" % (lat.latency / lat.count)

    return addrstr + avglat

# output
exiting = 0 if args.interval else 1
dist = b.get_table("hist_srtt")
lathash = b.get_table("latency")
seconds = 0
while (1):
    try:
        sleep(int(args.interval))
        seconds = seconds + int(args.interval)
    except KeyboardInterrupt:
        exiting = 1

    print()
    if args.timestamp:
        print("%-8s\n" % strftime("%H:%M:%S"), end="")

    dist.print_log2_hist(label, section_header=print_header, section_print_fn=print_section)
    dist.clear()
    if  htab_batch_ops:
        lathash.items_delete_batch()
    else:
        lathash.clear()

    if exiting or seconds >= args.duration:
        exit()

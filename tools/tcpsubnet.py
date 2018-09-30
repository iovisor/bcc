#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# tcpsubnet   Summarize TCP bytes sent to different subnets.
#             For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpsubnet [-h] [-v] [-J] [-f FORMAT] [-i INTERVAL] [subnets]
#
# This uses dynamic tracing of kernel functions, and will need to be updated
# to match kernel changes.
#
# This is an adaptation of tcptop from written by Brendan Gregg.
#
# WARNING: This traces all send at the TCP level, and while it
# summarizes data in-kernel to reduce overhead, there may still be some
# overhead at high TCP send/receive rates (eg, ~13% of one CPU at 100k TCP
# events/sec. This is not the same as packet rate: funccount can be used to
# count the kprobes below to find out the TCP rate). Test in a lab environment
# first. If your send rate is low (eg, <1k/sec) then the overhead is
# expected to be negligible.
#
# Copyright 2017 Rodrigo Manyari
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 03-Oct-2017   Rodrigo Manyari   Created this based on tcptop.
# 13-Feb-2018   Rodrigo Manyari   Fix pep8 errors, some refactoring.
# 05-Mar-2018   Rodrigo Manyari   Add date time to output.

import argparse
import json
import logging
import struct
import socket
from bcc import BPF
from datetime import datetime as dt
from time import sleep

# arguments
examples = """examples:
    ./tcpsubnet                 # Trace TCP sent to the default subnets:
                                # 127.0.0.1/32,10.0.0.0/8,172.16.0.0/12,
                                # 192.168.0.0/16,0.0.0.0/0
    ./tcpsubnet -f K            # Trace TCP sent to the default subnets
                                # aggregated in KBytes.
    ./tcpsubnet 10.80.0.0/24    # Trace TCP sent to 10.80.0.0/24 only
    ./tcpsubnet -J              # Format the output in JSON.
"""

default_subnets = "127.0.0.1/32,10.0.0.0/8," \
    "172.16.0.0/12,192.168.0.0/16,0.0.0.0/0"

parser = argparse.ArgumentParser(
    description="Summarize TCP send and aggregate by subnet",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("subnets", help="comma separated list of subnets",
    type=str, nargs="?", default=default_subnets)
parser.add_argument("-v", "--verbose", action="store_true",
    help="output debug statements")
parser.add_argument("-J", "--json", action="store_true",
    help="format output in JSON")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
parser.add_argument("-f", "--format", default="B",
    help="[bkmBKM] format to report: bits, Kbits, Mbits, bytes, " +
    "KBytes, MBytes (default B)", choices=["b", "k", "m", "B", "K", "M"])
parser.add_argument("-i", "--interval", default=1, type=int,
    help="output interval, in seconds (default 1)")
args = parser.parse_args()

level = logging.INFO
if args.verbose:
    level = logging.DEBUG

logging.basicConfig(level=level)

logging.debug("Starting with the following args:")
logging.debug(args)

# args checking
if int(args.interval) <= 0:
    logging.error("Invalid interval, must be > 0. Exiting.")
    exit(1)
else:
    args.interval = int(args.interval)

# map of supported formats
formats = {
    "b": lambda x: (x * 8),
    "k": lambda x: ((x * 8) / 1024),
    "m": lambda x: ((x * 8) / pow(1024, 2)),
    "B": lambda x: x,
    "K": lambda x: x / 1024,
    "M": lambda x: x / pow(1024, 2)
}

# Let's swap the string with the actual numeric value
# once here so we don't have to do it on every interval
formatFn = formats[args.format]

# define the basic structure of the BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct index_key_t {
  u32 index;
};

BPF_HASH(ipv4_send_bytes, struct index_key_t);

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t size)
{
    u16 family = sk->__sk_common.skc_family;

    if (family == AF_INET) {
        u32 dst = sk->__sk_common.skc_daddr;
        unsigned categorized = 0;
        __SUBNETS__
    }
    return 0;
}
"""


# Takes in a mask and returns the integer equivalent
# e.g.
# mask_to_int(8) returns 4278190080
def mask_to_int(n):
    return ((1 << n) - 1) << (32 - n)

# Takes in a list of subnets and returns a list
# of tuple-3 containing:
# - The subnet info at index 0
# - The addr portion as an int at index 1
# - The mask portion as an int at index 2
#
# e.g.
# parse_subnets([10.10.0.0/24]) returns
# [
#   ['10.10.0.0/24', 168427520, 4294967040],
# ]
def parse_subnets(subnets):
    m = []
    for s in subnets:
        parts = s.split("/")
        if len(parts) != 2:
            msg = "Subnet [%s] is invalid, please refer to the examples." % s
            raise ValueError(msg)
        netaddr_int = 0
        mask_int = 0
        try:
            netaddr_int = struct.unpack("!I", socket.inet_aton(parts[0]))[0]
        except:
            msg = ("Invalid net address in subnet [%s], " +
                "please refer to the examples.") % s
            raise ValueError(msg)
        try:
            mask_int = int(parts[1])
        except:
            msg = "Invalid mask in subnet [%s]. Mask must be an int" % s
            raise ValueError(msg)
        if mask_int < 0 or mask_int > 32:
            msg = ("Invalid mask in subnet [%s]. Must be an " +
                "int between 0 and 32.") % s
            raise ValueError(msg)
        mask_int = mask_to_int(int(parts[1]))
        m.append([s, netaddr_int, mask_int])
    return m

def generate_bpf_subnets(subnets):
    template = """
        if (!categorized && (__NET_ADDR__ & __NET_MASK__) ==
             (dst & __NET_MASK__)) {
          struct index_key_t key = {.index = __POS__};
          ipv4_send_bytes.increment(key, size);
          categorized = 1;
        }
    """
    bpf = ''
    for i, s in enumerate(subnets):
        branch = template
        branch = branch.replace("__NET_ADDR__", str(socket.htonl(s[1])))
        branch = branch.replace("__NET_MASK__", str(socket.htonl(s[2])))
        branch = branch.replace("__POS__", str(i))
        bpf += branch
    return bpf

subnets = []
if args.subnets:
    subnets = args.subnets.split(",")

subnets = parse_subnets(subnets)

logging.debug("Packets are going to be categorized in the following subnets:")
logging.debug(subnets)

bpf_subnets = generate_bpf_subnets(subnets)

# initialize BPF
bpf_text = bpf_text.replace("__SUBNETS__", bpf_subnets)

logging.debug("Done preprocessing the BPF program, " +
        "this is what will actually get executed:")
logging.debug(bpf_text)

if args.ebpf:
    print(bpf_text)
    exit()

b = BPF(text=bpf_text)

ipv4_send_bytes = b["ipv4_send_bytes"]

if not args.json:
    print("Tracing... Output every %d secs. Hit Ctrl-C to end" % args.interval)

# output
exiting = 0
while (1):

    try:
        sleep(args.interval)
    except KeyboardInterrupt:
        exiting = 1

    # IPv4:  build dict of all seen keys
    keys = ipv4_send_bytes
    for k, v in ipv4_send_bytes.items():
        if k not in keys:
            keys[k] = v

    # to hold json data
    data = {}

    # output
    now = dt.now()
    data['date'] = now.strftime('%x')
    data['time'] = now.strftime('%X')
    data['entries'] = {}
    if not args.json:
        print(now.strftime('[%x %X]'))
    for k, v in reversed(sorted(keys.items(), key=lambda keys: keys[1].value)):
        send_bytes = 0
        if k in ipv4_send_bytes:
            send_bytes = int(ipv4_send_bytes[k].value)
        subnet = subnets[k.index][0]
        send = formatFn(send_bytes)
        if args.json:
            data['entries'][subnet] = send
        else:
            print("%-21s %6d" % (subnet, send))

    if args.json:
        print(json.dumps(data))

    ipv4_send_bytes.clear()

    if exiting:
        exit(0)

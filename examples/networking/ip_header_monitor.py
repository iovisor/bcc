#!/usr/bin/python
#
# ip_header_monitor outputs every value in the ip header
# how to use : ip_header_monitor.py <net_interface> 
# 
# Copyright 2020 YoungEun Choe

from bcc import BPF
from ast import literal_eval
from ctypes import *
import ctypes as ct
import sys
import socket
import os
import struct

def help():
    print("execute: {0} <net_interface>".format(sys.argv[0]))
    print("e.g.: {0} eno1\n".format(sys.argv[0]))
    exit(1)

if len(sys.argv) != 2:
    help()
elif len(sys.argv) == 2:
    INTERFACE = sys.argv[1]

bpf_text = """

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/bpf.h>

#define IP_TCP 6
#define IP_UDP 17
#define IP_ICMP 1
#define ETH_HLEN 14

BPF_PERF_OUTPUT(skb_events);    

struct ip_hdr { 
    u32 ip_src;
    u32 ip_dst;  
    u16 ip_ttl;
    u16 ip_hchecksum;
    u16 ip_ver;
    u16 ip_hlen;
    u16 ip_tos;
    u16 ip_tlen;
    u16 ip_identification;
    u16 ip_nextp;
    u16 ip_ffo_unused;
    u16 ip_df;
    u16 ip_mf;
    u16 ip_foffset;
};

int ip_header_monitor(struct __sk_buff *skb) {
    u8 *cursor = 0;
    
    struct ip_hdr parsed;
    
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    if (!(ethernet -> type == 0x0800)) {
        return 0; // drop
    }

    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));

    parsed.ip_src = ip -> src;
    parsed.ip_dst = ip -> dst;
    parsed.ip_ttl = ip -> ttl;
    parsed.ip_hchecksum = ip->hchecksum;
    parsed.ip_ver = ip -> ver;
    parsed.ip_hlen = ip -> hlen;
    parsed.ip_tos = ip -> tos;
    parsed.ip_tlen = ip -> tlen;
    parsed.ip_identification = ip -> identification;
    parsed.ip_nextp = ip -> nextp;
    
    parsed.ip_ffo_unused = ip -> ffo_unused;
    parsed.ip_df = ip -> df;
    parsed.ip_mf = ip -> mf;
    parsed.ip_foffset = ip -> foffset;
    skb_events.perf_submit_skb(skb, skb->len, &parsed, sizeof(parsed)); // this one parses number as a hex to the user space
    
    return -1;
}

"""

# define a function to output perf output
def decimal_to_human(input_value):
    input_value = int(input_value)
    hex_value = hex(input_value)[2:]
    pt3 = literal_eval((str('0x'+str(hex_value[-2:]))))
    pt2 = literal_eval((str('0x'+str(hex_value[-4:-2]))))
    pt1 = literal_eval((str('0x'+str(hex_value[-6:-4]))))
    pt0 = literal_eval((str('0x'+str(hex_value[-8:-6]))))
    result = str(pt0)+'.'+str(pt1)+'.'+str(pt2)+'.'+str(pt3)
    return result

def print_skb_event(cpu, data, size):
    class SkbEvent(ct.Structure):
        _fields_ = [ ("ip_src", ct.c_uint32),
                    ("ip_dst", ct.c_uint32),
                    ("ip_ttl", ct.c_uint16),
                    ("ip_hchecksum", ct.c_uint16),
                    ("ip_ver", ct.c_uint16),
                    ("ip_hlen", ct.c_uint16),
                    ("ip_tos", ct.c_uint16),
                    ("ip_tlen", ct.c_uint16),
                    ("ip_identification", ct.c_uint16),
                    ("ip_nextp", ct.c_uint16),
                    ("ip_ffo_unused", ct.c_uint16),
                    ("ip_df", ct.c_uint16),
                    ("ip_mf", ct.c_uint16),
                    ("ip_foffset", ct.c_uint16)
                     ]
        
    skb_event = ct.cast(data, ct.POINTER(SkbEvent)).contents
    print("source : %s | destination : %s | ttl : %d | hchecksum : %d | ver : %d | hlen : %d | tos : %d\
            +| tlen : %d | identification : %d | nextp: %d | ffo_unused : %d | df :%d | mf : %d | foffset : %d"\
            % (decimal_to_human(str(skb_event.ip_src)), decimal_to_human(str(skb_event.ip_dst)), skb_event.ip_ttl,\
            skb_event.ip_hchecksum, skb_event.ip_ver, skb_event.ip_hlen, skb_event.ip_tos, skb_event.ip_tlen, \
            skb_event.ip_identification, skb_event.ip_nextp, skb_event.ip_ffo_unused, skb_event.ip_df, skb_event.ip_mf, \
            skb_event.ip_foffset))

bpf = BPF(text=bpf_text)

function_skb_matching = bpf.load_func("ip_header_monitor", BPF.SOCKET_FILTER)

BPF.attach_raw_socket(function_skb_matching, INTERFACE)

bpf["skb_events"].open_perf_buffer(print_skb_event)

try:
    while True :
        value = bpf.perf_buffer_poll()
except KeyboardInterrupt:
    pass

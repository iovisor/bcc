#!/usr/bin/python
#
# net_monitor.py Aggregates incoming network traffic
# outputs source ip, destination ip, the number of their network traffic, and current time
# how to use : net_monitor.py <net_interface> 
# 
# Copyright (c) 2020 YoungEun Choe

from bcc import BPF
import time
from ast import literal_eval
import sys

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
BPF_HASH(packet_cnt, u64, long, 256); 

int packet_monitor(struct __sk_buff *skb) {
    u8 *cursor = 0;
    u32 saddr, daddr;
    long* count = 0;
    long one = 1;
    u64 pass_value = 0;
    
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    if (ip->ver != 4)
        return 0;
    if (ip->nextp != IP_TCP) 
    {
        if (ip -> nextp != IP_UDP) 
        {
            if (ip -> nextp != IP_ICMP) 
                return 0; 
        }
    }
    
    saddr = ip -> src;
    daddr = ip -> dst;

    pass_value = saddr;
    pass_value = pass_value << 32;
    pass_value = pass_value + daddr;

    count = packet_cnt.lookup(&pass_value); 
    if (count)  // check if this map exists
        *count += 1;
    else        // if the map for the key doesn't exist, create one
        {
            packet_cnt.update(&pass_value, &one);
        }
    return -1;
}

"""

from ctypes import *
import ctypes as ct
import sys
import socket
import os
import struct
import ipaddress
import ctypes
from datetime import datetime

OUTPUT_INTERVAL = 1

bpf = BPF(text=bpf_text)

function_skb_matching = bpf.load_func("packet_monitor", BPF.SOCKET_FILTER)

BPF.attach_raw_socket(function_skb_matching, INTERFACE)

    # retrieeve packet_cnt map
packet_cnt = bpf.get_table('packet_cnt')    # retrieeve packet_cnt map

def decimal_to_human(input_value):
    try:
        decimal_ip = int(input_value)
        ip_string = str(ipaddress.IPv4Address(decimal_ip))
        return ip_string
    except ValueError:
        return "Invalid input"

try:
    while True :
        time.sleep(OUTPUT_INTERVAL)
        packet_cnt_output = packet_cnt.items()
        output_len = len(packet_cnt_output)
        current_time = datetime.now()
        formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
        if output_len != 0:
            print('\ncurrent packet nums:')
        
        for i in range(0,output_len):
            srcdst = packet_cnt_output[i][0].value
            src = (srcdst >> 32) & 0xFFFFFFFF
            dst = srcdst & 0xFFFFFFFF
            pkt_num = packet_cnt_output[i][1].value

            monitor_result = 'source address : ' + decimal_to_human(str(src)) + ' ' + 'destination address : ' + \
            decimal_to_human(str(dst)) + ' ' + str(pkt_num) + ' ' + 'time : ' + formatted_time
            print(monitor_result)

        packet_cnt.clear() # delete map entires after printing output. confiremd it deletes values and keys too 
        
except KeyboardInterrupt:
    sys.stdout.close()
    pass


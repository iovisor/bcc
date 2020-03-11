from bcc import BPF
import time
from ast import literal_eval

# To run this progrm, change the INTERFACE NAME below and run this program

INTERFACE = "br-mellanox"

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
    u32 saddr;
    u32 daddr;
    long* count = 0;
    long one = 1;
    u64 add_test = 0;
    
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    if (!(ethernet -> type == 0x0800)) {    
        return 0; // drop
    }

    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
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

    add_test = saddr;
    add_test = add_test << 32;
    add_test = add_test + daddr;

    count = packet_cnt.lookup(&add_test); 
    if (count)  // check if this map exists
        *count += 1;
    else        // if the map for the key doesn't exist, create one
        {
            packet_cnt.update(&add_test, &one);
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

# define a function to output perf output

tester_send = ''

OUTPUT_INTERVAL = 1

bpf = BPF(text=bpf_text)

function_skb_matching = bpf.load_func("packet_monitor", BPF.SOCKET_FILTER)

BPF.attach_raw_socket(function_skb_matching, INTERFACE)

    # retrieeve packet_cnt map
packet_cnt = bpf.get_table('packet_cnt')    # retrieeve packet_cnt map

#sys.stdout = open('myoutput.txt','w')

def decimal_to_human(input_value):
    input_value = int(input_value)
    hex_value = hex(input_value)[2:]
    pt3 = literal_eval((str('0x'+str(hex_value[-2:]))))
    pt2 = literal_eval((str('0x'+str(hex_value[-4:-2]))))
    pt1 = literal_eval((str('0x'+str(hex_value[-6:-4]))))
    pt0 = literal_eval((str('0x'+str(hex_value[-8:-6]))))
    result = str(pt0)+'.'+str(pt1)+'.'+str(pt2)+'.'+str(pt3)
    return result

print("=========================packet monitor=============================\n")

try:
    while True :
        time.sleep(OUTPUT_INTERVAL)
        packet_cnt_output = packet_cnt.items()
        output_len = len(packet_cnt_output)
        print('\n')
        for i in range(0,output_len):
            tester = int(str(packet_cnt_output[i][0])[8:-2]) # initial output omitted from the kernel space program
            tester = int(str(bin(tester))[2:]) # raw file
            src = int(str(tester)[:32],2) # part1 
            dst = int(str(tester)[32:],2)
            pkt_num = str(packet_cnt_output[i][1])[7:-1]

            monitor_result = 'source address : ' + decimal_to_human(str(src)) + ' ' + 'destination address : ' + decimal_to_human(str(dst)) + ' ' + pkt_num + ' ' + 'time : ' + str(time.localtime()[0])+';'+str(time.localtime()[1]).zfill(2)+';'+str(time.localtime()[2]).zfill(2)+';'+str(time.localtime()[3]).zfill(2)+';'+str(time.localtime()[4]).zfill(2)+';'+str(time.localtime()[5]).zfill(2)
            print(monitor_result)

            # time.time() outputs time elapsed since 00:00 hours, 1st, Jan., 1970.
        packet_cnt.clear() # delete map entires after printing output. confiremd it deletes values and keys too 
        
except KeyboardInterrupt:
    sys.stdout.close()
    pass


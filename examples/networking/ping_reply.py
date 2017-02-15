#!/usr/bin/env python
"""
ping_reply.py
    - Hooks at Traffic Control (ingress queue) in Kernel using eBPF
    - If packet is an ICMP echo (ping)
        * Intercepts the packet at traffic control ingress queue
        * Modifies ICMP packet type to ICMP reply
        * Swaps src/dst ip and mac and updates chksum
        * Redirects packet to the same interface as egress

USAGE: sudo python ping_reply.py
"""

from bcc import BPF
from pyroute2 import IPRoute, IPDB, protocols
import sys

prog = """
  #include <bcc/proto.h>
  #include <uapi/linux/if_ether.h>
  #include <uapi/linux/in.h>
  #include <uapi/linux/icmp.h>
  #include <uapi/linux/pkt_cls.h>

  /*
  struct icmp_t would come in handy for parsing ICMP packets,
  since bcc/proto.h doesn't specify a struct for parsing ICMP packets
  */
  struct icmp_t {
        unsigned char type;
        unsigned char code;
        unsigned short cksum;
        /* Fields only valid for echo-reply ICMP message */
        unsigned short id;
        unsigned short seq;
  } BPF_PACKET_HEADER;

  /*
  struct __sk_buff is passed by the kernel to this function
  */
  int ping_reply (struct __sk_buff * skb) {
        // Packet is available on the 0th location of the memory.
        u8 *cursor = 0;

        struct ethernet_t * ethernet = cursor_advance(cursor,
                sizeof(*ethernet));
        // If packet type is not IP, return
        if (ethernet->type != ETH_P_IP)
                return 0;

        struct ip_t * ip = (struct ip_t *) cursor;
        u32 len = ip->hlen << 2;
        cursor_advance(cursor, len);

        // If next protocol is not ICMP, return
        if (ip->nextp != IPPROTO_ICMP)
                return 0;

        struct icmp_t * icmp = cursor_advance(cursor, sizeof(*icmp));
        // If ICMP packet is not echo, return
        if (icmp->type != ICMP_ECHO)
                return 0;

        /*
        Converting ICMP echo into ICMP reply by changing the type to 0
        Since we're changing packet contents, we need to update the checksum
        */
        unsigned short type = ICMP_ECHOREPLY;
        //incr_cksum_l4(&icmp->cksum, icmp->type, type, 1);
        bpf_l4_csum_replace(skb,36,icmp->type, type,sizeof(type));
        icmp->type = type;

        /*
        Swapping Source and Destination in IP header
        We don't need to update checksum since we're just swapping.
        However to demonstrate the use of incr_cksum_l3, the checksum
        is recomputed after each change
        */
        u32 old_src = ip->src;
        u32 old_dst = ip->dst;

        incr_cksum_l3(&ip->hchecksum, old_src, old_dst);
        ip->src = old_dst;
        incr_cksum_l3(&ip->hchecksum, old_dst, old_src);
        ip->dst = old_src;

        /* Swapping Mac Addresses
        Using two temp variables since assigning one memory location
        to another directly causes a compilation error.
        */
        u64 old_src_mac = ethernet->src;
        u64 old_dst_mac = ethernet->dst;

        ethernet->src = old_dst_mac;
        ethernet->dst = old_src_mac;

        u64 ret = bpf_redirect(skb->ifindex, 0 /*For Egress */);
        /*
        This output to the kernel trace_pipe which can also be read by:
        cat /sys/kernel/debug/tracing/trace_pipe
        */
        bpf_trace_printk("ICMP_SEQ: %u\\n", icmp->seq);
        return TC_ACT_REDIRECT;
}
"""
ipr = IPRoute()
ipdb = IPDB(nl=ipr)
ifc = ipdb.interfaces.eth0

b = BPF(text=prog)
pr = b.load_func("ping_reply", BPF.SCHED_ACT)
ipr.tc("add", "ingress", ifc.index, "ffff:")
action = {"kind": "bpf", "fd": pr.fd, "name": pr.name, "action": "ok"}
ipr.tc("add-filter", "u32", ifc.index, ":1", parent="ffff:", action=[action],
    protocol=protocols.ETH_P_ALL, classid=1, target=0x10000, keys=['0x0/0x0+0'])

try:
    print "All Ready..."
    b.trace_print()
except KeyboardInterrupt:
    print "Ending Demo..."
finally:
    ipr.tc("del", "ingress", ifc.index, "ffff:")
    ipdb.release()

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
from pyroute2 import IPRoute, IPDB
import sys

prog = """
  #include <bcc/proto.h>

  #define IP_SRC_OFF 26
  #define IP_DST_OFF 30
  #define IP_CKSUM_OFF 24
  /*
  There are better ways to get OFFSETs for e.g. by using macros from .h
  files of other networking subsytems
  */

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
        if (ethernet->type != 0x800)
                return 0;

        struct ip_t * ip = cursor_advance(cursor, sizeof(*ip));
        // If next protocol is not ICMP, return
        if (ip->nextp != 0x01)
                return 0;

        struct icmp_t * icmp = cursor_advance(cursor, sizeof(*icmp));
        // If ICMP packet is not echo, return
        if (icmp->type != 8 || icmp->code != 0)
                return 0;

        /*
        Converting ICMP echo into ICMP reply by changing the type to 0
        Since we're changing packet contents, we need to update the checksum
        */
        unsigned short type = 0;
        bpf_l4_csum_replace(skb,36,icmp->type, type,sizeof(type));
        bpf_skb_store_bytes(skb, 34, &type, sizeof(type),0);

        /*
        Swapping Source and Destination in IP header
        We don't need to update checksum since we're just swapping.
        However to demonstrate the use of bpf_l3_csum_replace, the checksum
        is recomputed after each change
        */
        unsigned int old_src = bpf_ntohl(ip->src);
        unsigned int old_dst = bpf_ntohl(ip->dst);

        bpf_l3_csum_replace(skb, IP_CKSUM_OFF, old_src, old_dst,
                sizeof(old_dst));

        /*
        Demonstrating the use of bpf_skb_store_bytes(...)
        There are other easier ways to swap ip->src and ip->dst, one of which
        follows while swapping mac addresses
        */
        bpf_skb_store_bytes(skb, IP_SRC_OFF, &old_dst,
                sizeof(old_dst), 0);

        bpf_l3_csum_replace(skb, IP_CKSUM_OFF, old_dst, old_src,
                sizeof(old_src));
        bpf_skb_store_bytes(skb, IP_DST_OFF, &old_src, sizeof(old_src), 0);

        /* Swapping Mac Addresses
        Using two temp variables since assigning one memory location
        to another directly causes a compilation error.
        */
        unsigned long long old_src_mac = ethernet->src;
        unsigned long long old_dst_mac = ethernet->dst;

        ethernet->src = old_dst_mac;
        ethernet->dst = old_src_mac;

        u64 ret = bpf_clone_redirect(skb, skb->ifindex,0 /*For Egress */);
        /*
        This output to the kernel trace_pipe which can also be read by:
        cat /sys/kernel/debug/tracing/trace_pipe
        */
        bpf_trace_printk("Replying to ICMP echo: Result=%u\\n", ret);

        return 1;
}
"""
ipr = IPRoute()
ipdb = IPDB(nl=ipr)
ifc = ipdb.interfaces.eth0

b = BPF(text=prog)
pbr = b.load_func("ping_reply", BPF.SCHED_CLS)
ipr.tc("add", "ingress", ifc.index, "ffff:")
ipr.tc("add-filter", "bpf", ifc.index, ":1", fd=pbr.fd,
       name=pbr.name, parent="ffff:", action="drop", classid=1)

try:
    print "All Ready..."
    b.trace_print()
except KeyboardInterrupt:
    print "Ending Demo..."
finally:
    ipr.tc("del", "ingress", ifc.index, "ffff:")
    ipdb.release()

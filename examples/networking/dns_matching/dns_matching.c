/*
 * dns_matching.c  Drop DNS packets requesting DNS name contained in hash map
 *    For Linux, uses BCC, eBPF. See .py file.
 *
 * Copyright (c) 2016 Rudi Floren.
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * 11-May-2016  Rudi Floren Created this.
 */

#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/udp.h>
#include <bcc/proto.h>

#define ETH_LEN 14

struct dns_hdr_t
{
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} BPF_PACKET_HEADER;


struct dns_query_flags_t
{
  uint16_t qtype;
  uint16_t qclass;
} BPF_PACKET_HEADER;

struct dns_char_t
{
    char c;
} BPF_PACKET_HEADER;

struct Key {
  unsigned char p[255];
};

struct Leaf {
  // Not really needed in this example
  unsigned char p[4];
};

BPF_HASH(cache, struct Key, struct Leaf, 128);

int dns_matching(struct __sk_buff *skb)
{
  u8 *cursor = 0;
  struct Key key = {};
  // Check of ethernet/IP frame.
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  if(ethernet->type == ETH_P_IP) {

    // Check for UDP.
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    u16 hlen_bytes = ip->hlen << 2;
    if(ip->nextp == IPPROTO_UDP) {

      // Check for Port 53, DNS packet.
      struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));
      if(udp->dport == 53){

        struct dns_hdr_t *dns_hdr = cursor_advance(cursor, sizeof(*dns_hdr));

        // Do nothing if packet is not a request.
        if((dns_hdr->flags >>15) != 0) {
          // Exit if this packet is not a request.
          return -1;
        }

        u16 i = 0;
        struct dns_char_t *c;
        #pragma unroll
        for(i = 0; i<255;i++){
          c = cursor_advance(cursor, 1);
          if (c->c == 0)
            break;
          key.p[i] = c->c;
        }

        struct Leaf * lookup_leaf = cache.lookup(&key);

        // If DNS name is contained in our map, keep the packet
        if(lookup_leaf) {
          bpf_trace_printk("Matched1\n");
          return -1;
        }
      }
    }
  }
  // Drop the packet
  return 0;
}

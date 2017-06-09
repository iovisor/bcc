// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")
#include <bcc/proto.h>
struct IPKey {
  u32 dip;
  u32 sip;
};
struct IPLeaf {
  u32 xdip;
  u32 xsip;
  u64 ip_xlated_pkts;
  u64 arp_xlated_pkts;
};
BPF_HASH(xlate, struct IPKey, struct IPLeaf, 1024);

int on_packet(struct __sk_buff *skb) {
  u8 *cursor = 0;

  u32 orig_dip = 0;
  u32 orig_sip = 0;
  struct IPLeaf xleaf = {};

  ethernet: {
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    switch (ethernet->type) {
      case ETH_P_IP: goto ip;
      case ETH_P_ARP: goto arp;
      case ETH_P_8021Q: goto dot1q;
      default: goto EOP;
    }
  }

  dot1q: {
    struct dot1q_t *dot1q = cursor_advance(cursor, sizeof(*dot1q));
    switch (dot1q->type) {
      case ETH_P_IP: goto ip;
      case ETH_P_ARP: goto arp;
      default: goto EOP;
    }
  }

  arp: {
    struct arp_t *arp = cursor_advance(cursor, sizeof(*arp));
    orig_dip = arp->tpa;
    orig_sip = arp->spa;
    struct IPKey key = {.dip=orig_dip, .sip=orig_sip};
    struct IPLeaf *xleafp = xlate.lookup(&key);
    if (xleafp) {
      xleaf = *xleafp;
      arp->tpa = xleaf.xdip;
      arp->spa = xleaf.xsip;
      lock_xadd(&xleafp->arp_xlated_pkts, 1);
    }
    goto EOP;
  }

  ip: {
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    orig_dip = ip->dst;
    orig_sip = ip->src;
    struct IPKey key = {.dip=orig_dip, .sip=orig_sip};
    struct IPLeaf *xleafp = xlate.lookup(&key);
    if (xleafp) {
      xleaf = *xleafp;
      ip->dst = xleaf.xdip;
      incr_cksum_l3(&ip->hchecksum, orig_dip, xleaf.xdip);
      ip->src = xleaf.xsip;
      incr_cksum_l3(&ip->hchecksum, orig_sip, xleaf.xsip);
      lock_xadd(&xleafp->ip_xlated_pkts, 1);
    }
    switch (ip->nextp) {
      case 6: goto tcp;
      case 17: goto udp;
      default: goto EOP;
    }
  }

  udp: {
    struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));
    if (xleaf.xdip) {
      incr_cksum_l4(&udp->crc, orig_dip, xleaf.xdip, 1);
      incr_cksum_l4(&udp->crc, orig_sip, xleaf.xsip, 1);
    }
    goto EOP;
  }

  tcp: {
    struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));
    if (xleaf.xdip) {
      incr_cksum_l4(&tcp->cksum, orig_dip, xleaf.xdip, 1);
      incr_cksum_l4(&tcp->cksum, orig_sip, xleaf.xsip, 1);
    }
    goto EOP;
  }

EOP:
  return 0;
}

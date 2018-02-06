// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")
#include <bcc/proto.h>

struct ipkey {
  u32 inner_sip;
  u32 inner_dip;
  u32 outer_sip;
  u32 outer_dip;
  u32 vni;
};
struct counters {
  u64 tx_pkts;
  u64 rx_pkts;
  u64 tx_bytes;
  u64 rx_bytes;
};

BPF_HASH(stats, struct ipkey, struct counters, 1024);
BPF_PROG_ARRAY(parser, 10);

enum cb_index {
  CB_FLAGS = 0,
  CB_SIP,
  CB_DIP,
  CB_VNI,
  CB_OFFSET,
};

// helper func to swap two memory locations
static inline
void swap32(u32 *a, u32 *b) {
  u32 t = *a;
  *a = *b;
  *b = t;
}

// helper to swap the fields in an ipkey to give consistent ordering
static inline
void swap_ipkey(struct ipkey *key) {
  swap32(&key->outer_sip, &key->outer_dip);
  swap32(&key->inner_sip, &key->inner_dip);
}

#define IS_INGRESS 0x1
// initial handler for each packet on an ingress tc filter
int handle_ingress(struct __sk_buff *skb) {
  skb->cb[CB_FLAGS] = IS_INGRESS;
  parser.call(skb, 1);  // jump to generic packet parser
  return 1;
}

// initial handler for each packet on an egress tc filter
int handle_egress(struct __sk_buff *skb) {
  skb->cb[CB_FLAGS] = 0;
  parser.call(skb, 1);  // jump to generic packet parser
  return 1;
}

// parse the outer vxlan frame
int handle_outer(struct __sk_buff *skb) {
  u8 *cursor = 0;

  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

  // filter bcast/mcast from the stats
  if (ethernet->dst & (1ull << 40))
    goto finish;

  switch (ethernet->type) {
    case 0x0800: goto ip;
    default: goto finish;
  }

ip: ;
  struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
  skb->cb[CB_SIP] = ip->src;
  skb->cb[CB_DIP] = ip->dst;

  switch (ip->nextp) {
    case 17: goto udp;
    default: goto finish;
  }

udp: ;
  struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));
  switch (udp->dport) {
    case 4789: goto vxlan;
    default: goto finish;
  }

vxlan: ;
  struct vxlan_t *vxlan = cursor_advance(cursor, sizeof(*vxlan));
  skb->cb[CB_VNI] = vxlan->key;
  skb->cb[CB_OFFSET] = (u64)vxlan + sizeof(*vxlan);
  parser.call(skb, 2);

finish:
  return 1;
}

// Parse the inner frame, whatever it may be. If it is ipv4, add the inner
// source/dest ip to the key, for finer grained stats
int handle_inner(struct __sk_buff *skb) {
  int is_ingress = skb->cb[CB_FLAGS] & IS_INGRESS;
  struct ipkey key = {
    .vni=skb->cb[CB_VNI],
    .outer_sip = skb->cb[CB_SIP],
    .outer_dip = skb->cb[CB_DIP]
  };
  u8 *cursor = (u8 *)(u64)skb->cb[CB_OFFSET];

  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  switch (ethernet->type) {
    case 0x0800: goto ip;
    default: goto finish;
  }
ip: ;
  struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
  key.inner_sip = ip->src;
  key.inner_dip = ip->dst;

finish:
  // consistent ordering
  if (key.outer_dip < key.outer_sip)
    swap_ipkey(&key);
  struct counters zleaf = {0};
  struct counters *leaf = stats.lookup_or_init(&key, &zleaf);
  if (is_ingress) {
    lock_xadd(&leaf->rx_pkts, 1);
    lock_xadd(&leaf->rx_bytes, skb->len);
  } else {
    lock_xadd(&leaf->tx_pkts, 1);
    lock_xadd(&leaf->tx_bytes, skb->len);
  }
  return 1;
}

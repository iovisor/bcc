// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")

#include <bcc/proto.h>

struct IPKey {
  u32 dip;
  u32 sip;
};
struct IPLeaf {
  u64 rx_pkts;
  u64 tx_pkts;
};

BPF_HASH(stats, struct IPKey, struct IPLeaf, 256);

int on_packet(struct __sk_buff *skb) {
  u8 *cursor = 0;
  ethernet: {
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    switch (ethernet->type) {
        case ETH_P_IP: goto ip;
        case ETH_P_8021Q: goto dot1q;
        default: goto EOP;
    }
  }

  dot1q: {
    struct dot1q_t *dot1q = cursor_advance(cursor, sizeof(*dot1q));
    switch (dot1q->type) {
      case ETH_P_8021Q: goto ip;
      default: goto EOP;
    }
  }

  ip: {
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    int rx = 0, tx = 0;
    struct IPKey key;
    if (ip->dst > ip->src) {
      key.dip = ip->dst;
      key.sip = ip->src;
      rx = 1;
    } else {
      key.dip = ip->src;
      key.sip = ip->dst;
      tx = 1;
    }
    struct IPLeaf zleaf = {0};
    struct IPLeaf *leaf = stats.lookup_or_init(&key, &zleaf);
    lock_xadd(&leaf->rx_pkts, rx);
    lock_xadd(&leaf->tx_pkts, tx);
  }

EOP:
  return 0;
}

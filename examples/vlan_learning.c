// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")

#include <bcc/proto.h>

struct ifindex_leaf_t {
  int out_ifindex;
  u64 tx_pkts;
  u64 tx_bytes;
};

// redirect based on mac -> out_ifindex (auto-learning)
BPF_TABLE("hash", int, struct ifindex_leaf_t, egress, 4096);

// redirect based on mac -> out_ifindex (config-driven)
BPF_TABLE("hash", u64, struct ifindex_leaf_t, ingress, 4096);

int handle_phys2virt(struct __sk_buff *skb) {
  u8 *cursor = 0;
  ethernet: {
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    struct ifindex_leaf_t *leaf = ingress.lookup(ethernet->src);
    if (leaf) {
      lock_xadd(&leaf->tx_pkts, 1);
      lock_xadd(&leaf->tx_bytes, skb->len);
      // auto-program reverse direction table
      struct ifindex_leaf_t *out_leaf = egress.lookup_or_init(leaf->out_ifindex, (struct ifindex_leaf_t){0});
      // relearn when mac moves ifindex
      if (out_leaf->out_ifindex != skb->ifindex)
        out_leaf->out_ifindex = skb->ifindex;
      bpf_clone_redirect(skb, leaf->out_ifindex, 0);
    }
  }
  return 1;
}

int handle_virt2phys(struct __sk_buff *skb) {
  u8 *cursor = 0;
  ethernet: {
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    struct ifindex_leaf_t *leaf = egress.lookup(skb->ifindex);
    if (leaf) {
      lock_xadd(&leaf->tx_pkts, 1);
      lock_xadd(&leaf->tx_bytes, skb->len);
      bpf_clone_redirect(skb, leaf->out_ifindex, 0);
    }
  }
  return 1;
}

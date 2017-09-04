// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")

#include <bcc/proto.h>

struct ifindex_leaf_t {
  int out_ifindex;
  int vlan_tci; // populated by phys2virt and used by virt2phys
  int vlan_proto; // populated by phys2virt and used by virt2phys
  u64 tx_pkts;
  u64 tx_bytes;
};

// redirect based on mac -> out_ifindex (auto-learning)
BPF_HASH(egress, int, struct ifindex_leaf_t, 4096);

// redirect based on mac -> out_ifindex (config-driven)
BPF_HASH(ingress, u64, struct ifindex_leaf_t, 4096);

int handle_phys2virt(struct __sk_buff *skb) {
  // only handle vlan packets
  if (!skb->vlan_present)
    return 1;
  u8 *cursor = 0;
  ethernet: {
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    u64 src_mac = ethernet->src;
    struct ifindex_leaf_t *leaf = ingress.lookup(&src_mac);
    if (leaf) {
      lock_xadd(&leaf->tx_pkts, 1);
      lock_xadd(&leaf->tx_bytes, skb->len);
      // auto-program reverse direction table
      int out_ifindex = leaf->out_ifindex;
      struct ifindex_leaf_t zleaf = {0};
      struct ifindex_leaf_t *out_leaf = egress.lookup_or_init(&out_ifindex, &zleaf);
      // to capture potential configuration changes
      out_leaf->out_ifindex = skb->ifindex;
      out_leaf->vlan_tci = skb->vlan_tci;
      out_leaf->vlan_proto = skb->vlan_proto;
      // pop the vlan header and send to the destination
      bpf_skb_vlan_pop(skb);
      bpf_clone_redirect(skb, leaf->out_ifindex, 0);
    }
  }
  return 1;
}

int handle_virt2phys(struct __sk_buff *skb) {
  u8 *cursor = 0;
  ethernet: {
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    int src_ifindex = skb->ifindex;
    struct ifindex_leaf_t *leaf = egress.lookup(&src_ifindex);
    if (leaf) {
      lock_xadd(&leaf->tx_pkts, 1);
      lock_xadd(&leaf->tx_bytes, skb->len);
      bpf_skb_vlan_push(skb, leaf->vlan_proto, leaf->vlan_tci);
      bpf_clone_redirect(skb, leaf->out_ifindex, 0);
    }
  }
  return 1;
}

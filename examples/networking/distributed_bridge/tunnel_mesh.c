// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")
#include <bcc/proto.h>

struct config {
  int tunnel_ifindex;
};
BPF_HASH(conf, int, struct config, 1);

struct tunnel_key {
  u32 tunnel_id;
  u32 remote_ipv4;
};
BPF_HASH(tunkey2if, struct tunnel_key, int, 1024);

BPF_HASH(if2tunkey, int, struct tunnel_key, 1024);

// Handle packets from the encap device, demux into the dest tenant
int handle_ingress(struct __sk_buff *skb) {
  struct bpf_tunnel_key tkey = {};
  struct tunnel_key key;
  bpf_skb_get_tunnel_key(skb, &tkey,
      offsetof(struct bpf_tunnel_key, remote_ipv6[1]), 0);

  key.tunnel_id = tkey.tunnel_id;
  key.remote_ipv4 = tkey.remote_ipv4;
  int *ifindex = tunkey2if.lookup(&key);
  if (ifindex) {
    //bpf_trace_printk("ingress tunnel_id=%d remote_ip=%08x ifindex=%d\n",
    //                 key.tunnel_id, key.remote_ipv4, *ifindex);
    // mark from external
    skb->tc_index = 1;
    bpf_clone_redirect(skb, *ifindex, 1/*ingress*/);
  } else {
    bpf_trace_printk("ingress invalid tunnel_id=%d\n", key.tunnel_id);
  }

  return 1;
}

// Handle packets from the tenant, mux into the encap device
int handle_egress(struct __sk_buff *skb) {
  int ifindex = skb->ifindex;
  struct bpf_tunnel_key tkey = {};
  struct tunnel_key *key_p;
  int one = 1;
  struct config *cfg = conf.lookup(&one);

  if (!cfg) return 1;

  if (skb->tc_index) {
    //bpf_trace_printk("from external\n");
    // don't send it back out to encap device
    return 1;
  }

  key_p = if2tunkey.lookup(&ifindex);
  if (key_p) {
    tkey.tunnel_id = key_p->tunnel_id;
    tkey.remote_ipv4 = key_p->remote_ipv4;
    bpf_skb_set_tunnel_key(skb, &tkey,
        offsetof(struct bpf_tunnel_key, remote_ipv6[1]), 0);
    bpf_clone_redirect(skb, cfg->tunnel_ifindex, 0/*egress*/);
  }
  return 1;
}

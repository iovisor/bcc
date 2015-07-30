// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")
#include <bcc/proto.h>

struct config {
  int tunnel_ifindex;
};
BPF_TABLE("hash", int, struct config, conf, 1);

BPF_TABLE("hash", struct bpf_tunnel_key, int, tunkey2if, 1024);

BPF_TABLE("hash", int, struct bpf_tunnel_key, if2tunkey, 1024);

// Handle packets from the encap device, demux into the dest tenant
int handle_ingress(struct __sk_buff *skb) {
  struct bpf_tunnel_key tkey = {};
  bpf_skb_get_tunnel_key(skb, &tkey, sizeof(tkey), 0);

  int *ifindex = tunkey2if.lookup(&tkey);
  if (ifindex) {
    //bpf_trace_printk("ingress tunnel_id=%d remote_ip=%08x ifindex=%d\n",
    //                 tkey.tunnel_id, tkey.remote_ipv4, *ifindex);
    // mark from external
    skb->tc_index = 1;
    bpf_clone_redirect(skb, *ifindex, 1/*ingress*/);
  } else {
    bpf_trace_printk("ingress invalid tunnel_id=%d\n", tkey.tunnel_id);
  }

  return 1;
}

// Handle packets from the tenant, mux into the encap device
int handle_egress(struct __sk_buff *skb) {
  int ifindex = skb->ifindex;
  struct bpf_tunnel_key *tkey_p, tkey = {};
  int one = 1;
  struct config *cfg = conf.lookup(&one);

  if (!cfg) return 1;

  if (skb->tc_index) {
    //bpf_trace_printk("from external\n");
    // don't send it back out to encap device
    return 1;
  }

  tkey_p = if2tunkey.lookup(&ifindex);
  if (tkey_p) {
    tkey.tunnel_id = tkey_p->tunnel_id;
    tkey.remote_ipv4 = tkey_p->remote_ipv4;
    bpf_skb_set_tunnel_key(skb, &tkey, sizeof(tkey), 0);
    bpf_clone_redirect(skb, cfg->tunnel_ifindex, 0/*egress*/);
  }
  return 1;
}

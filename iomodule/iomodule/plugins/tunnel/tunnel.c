// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")
#include <bcc/proto.h>
#include <uapi/linux/pkt_cls.h>

BPF_TABLE("prog", int, int, forward, 65536);
static int ifc_send(struct __sk_buff *skb, int out) {
  //bpf_trace_printk("tunnel: ifc_send %p %d\n", skb, out);
  if (out < 0) {
    out = -out;
    // ports are programmed in the table in odd/even pairs
    skb->cb[0] = -(out ^ 1);
    forward.call(skb, out);
  } else {
    bpf_clone_redirect(skb, out, 0);
  }
  return TC_ACT_SHOT;
}


struct config {
  int tunnel_ifindex;
};
BPF_TABLE("hash", int, struct config, conf, 1);

BPF_TABLE("hash", struct bpf_tunnel_key, int, tunkey2if, 1024);

BPF_TABLE("hash", int, struct bpf_tunnel_key, if2tunkey, 1024);

// Handle packets from the encap device, demux into the dest tenant
int recv_tunnel(struct __sk_buff *skb) {
  struct bpf_tunnel_key tkey = {};
  bpf_skb_get_tunnel_key(skb, &tkey, sizeof(tkey), 0);

  int *ifindex = tunkey2if.lookup(&tkey);
  if (ifindex) {
    //bpf_trace_printk("ingress tunnel_id=%d remote_ip=%08x ifindex=%d\n",
    //                 tkey.tunnel_id, tkey.remote_ipv4, *ifindex);
    // mark from external
    skb->tc_index = 1;
    ifc_send(skb, *ifindex);
  } else {
    bpf_trace_printk("ingress invalid tunnel_id=%d\n", tkey.tunnel_id);
  }

  return TC_ACT_SHOT;
}

// Handle packets from the tenant, mux into the encap device
int recv_local(struct __sk_buff *skb) {
  int ifindex = skb->cb[0];
  struct bpf_tunnel_key *tkey_p, tkey = {};
  int one = 1;
  struct config *cfg = conf.lookup(&one);

  if (!cfg) return TC_ACT_SHOT;

  if (skb->tc_index) {
    bpf_trace_printk("from external\n");
    // don't send it back out to encap device
    return 1;
  }

  tkey_p = if2tunkey.lookup(&ifindex);
  if (tkey_p) {
    tkey.tunnel_id = tkey_p->tunnel_id;
    tkey.remote_ipv4 = tkey_p->remote_ipv4;
    bpf_skb_set_tunnel_key(skb, &tkey, sizeof(tkey), 0);
    ifc_send(skb, cfg->tunnel_ifindex);
  }
  return TC_ACT_SHOT;
}

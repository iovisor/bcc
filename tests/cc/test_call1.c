// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")

BPF_TABLE("prog", int, int, jump, 64);
BPF_TABLE("array", int, u64, stats, 64);

enum states {
  S_EOP = 1,
  S_ETHER,
  S_ARP,
  S_IP
};

int parse_ether(struct __sk_buff *skb) {
  size_t cur = 0;
  size_t next = cur + 14;

  u64 *leaf = stats.lookup(S_ETHER);
  if (leaf) (*leaf)++;

  switch (bpf_dext_pkt(skb, cur + 12, 0, 16)) {
    case 0x0800: jump.call(skb, S_IP);
    case 0x0806: jump.call(skb, S_ARP);
  }
  jump.call(skb, S_EOP);
  return 1;
}

int parse_arp(struct __sk_buff *skb) {
  size_t cur = 14;  // TODO: get from ctx
  size_t next = cur + 28;

  u64 *leaf = stats.lookup(S_ARP);
  if (leaf) (*leaf)++;

  jump.call(skb, S_EOP);
  return 1;
}

int parse_ip(struct __sk_buff *skb) {
  size_t cur = 14;  // TODO: get from ctx
  size_t next = cur + 20;

  u64 *leaf = stats.lookup(S_IP);
  if (leaf) (*leaf)++;

  jump.call(skb, S_EOP);
  return 1;
}

int eop(struct __sk_buff *skb) {
  u64 *leaf = stats.lookup(S_EOP);
  if (leaf) (*leaf)++;
  return 1;
}

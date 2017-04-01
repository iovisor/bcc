// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")

#include <bcc/proto.h>

struct ipkey {
  u32 client_ip;
};

BPF_HASH(learned_ips, struct ipkey, int, 1024);

// trivial action
int pass(struct __sk_buff *skb) {
  return 1;
}

// Process each wan packet, and determine if the packet is in the IP
// table or not. Learned IPs are rate-limited and unclassified are not.
// returns: > 0 when an IP is known
//          = 0 when an IP is not known, or non-IP traffic
int classify_wan(struct __sk_buff *skb) {
  u8 *cursor = 0;
  ethernet: {
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    switch (ethernet->type) {
      case ETH_P_IP: goto ip;
      default: goto EOP;
    }
  }
  ip: {
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    u32 dip = ip->dst;
    struct ipkey key = {.client_ip=dip};
    int *val = learned_ips.lookup(&key);
    if (val)
      return *val;
    goto EOP;
  }
EOP:
  return 0;
}

// Process each neighbor packet, and store the source IP in the learned table.
// Mark the inserted entry with a non-zero value to be used by the classify_wan
// lookup.
int classify_neighbor(struct __sk_buff *skb) {
  u8 *cursor = 0;
  ethernet: {
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    switch (ethernet->type) {
      case ETH_P_IP: goto ip;
      default: goto EOP;
    }
  }
  ip: {
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    u32 sip = ip->src;
    struct ipkey key = {.client_ip=sip};
    int val = 1;
    learned_ips.insert(&key, &val);
    goto EOP;
  }
EOP:
  return 1;
}

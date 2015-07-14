// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")

#include <bcc/proto.h>

// hash
typedef struct {
  u32 dip:32;
} FwdKey;
typedef struct {
  u32 fwd_idx:32;
} FwdLeaf;
BPF_TABLE("hash", FwdKey, FwdLeaf, fwd_map, 1);

// array
typedef struct {
  u32 index;
} ConfigKey;
typedef struct {
  u32 bpfdev_ip;
  u32 slave_ip;
} ConfigLeaf;
BPF_TABLE("array", ConfigKey, ConfigLeaf, config_map, 1);

// hash
typedef struct {
  u32 ip;
} MacaddrKey;
typedef struct {
  u64 mac;
} MacaddrLeaf;
BPF_TABLE("hash", MacaddrKey, MacaddrLeaf, macaddr_map, 11);

// hash
typedef struct {
  u32 slave_ip;
} SlaveKey;
typedef struct {
  u32 slave_ifindex;
} SlaveLeaf;
BPF_TABLE("hash", SlaveKey, SlaveLeaf, slave_map, 10);

int handle_packet(struct __sk_buff *skb) {
  int ret = 0;
  u8 *cursor = 0;

  if (skb->pkt_type == 0) {
    // tx
    // make sure configured
    u32 slave_ip;

    ConfigLeaf *cfg_leaf = config_map.lookup((ConfigKey){0});
    if (cfg_leaf) {
      slave_ip = cfg_leaf->slave_ip;
    } else {
      return 0xffffffff;
    }

    // make sure slave configured
    // tx, default to the single slave
    SlaveLeaf *slave_leaf = slave_map.lookup((SlaveKey){slave_ip});
    if (slave_leaf) {
      ret = slave_leaf->slave_ifindex;
    } else {
      return 0xffffffff;
    }
  } else {
    // rx, default to stack
    ret = 0;
  }

  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  switch (ethernet->type) {
    case ETH_P_IP: goto ip;
    case ETH_P_ARP: goto arp;
    case ETH_P_8021Q: goto dot1q;
    default: goto EOP;
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
    if (skb->pkt_type) {
      if (arp->oper == 1) {
        macaddr_map.update((MacaddrKey){arp->spa}, (MacaddrLeaf){arp->sha});
      }
    }
    goto EOP;
  }

  struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
  ip: {
    switch (ip->nextp) {
      case 6: goto tcp;
      case 17: goto udp;
      default: goto EOP;
    }
  }
  tcp: {
    struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));
    goto EOP;
  }
  udp: {
    struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));
    if (udp->dport != 5000) {
       goto EOP;
    }
    if (skb->pkt_type) {
      // lookup and then forward
      FwdLeaf *fwd_val = fwd_map.lookup((FwdKey){ip->dst});
      if (fwd_val) {
         return fwd_val->fwd_idx;
      }
    } else {
      // rewrite the packet and send to a pre-configured index if needed
      u32 new_ip;
      u32 old_ip;
      u64 src_mac;
      u64 dst_mac;

      ConfigLeaf *cfg_leaf = config_map.lookup((ConfigKey){0});
      if (cfg_leaf) {
        MacaddrLeaf *mac_leaf;

        mac_leaf = macaddr_map.lookup((MacaddrKey){cfg_leaf->bpfdev_ip});
        if (mac_leaf) {
          src_mac = mac_leaf->mac;
        } else {
          goto EOP;
        }

        mac_leaf = macaddr_map.lookup((MacaddrKey){cfg_leaf->slave_ip});
        if (mac_leaf) {
          dst_mac = mac_leaf->mac;
        } else {
          goto EOP;
        }

        // rewrite ethernet header
        ethernet->dst = dst_mac;
        ethernet->src = src_mac;

        // ip & udp checksum
        incr_cksum_l4(&udp->crc, ip->src, cfg_leaf->bpfdev_ip, 1);
        incr_cksum_l4(&udp->crc, ip->dst, cfg_leaf->slave_ip, 1);

        // rewrite ip src/dst fields
        ip->src = cfg_leaf->bpfdev_ip;
        ip->dst = cfg_leaf->slave_ip;
      }
    }
    goto EOP;
  }

EOP:
  return ret;
}

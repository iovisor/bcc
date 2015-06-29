// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")

#include <bcc/proto.h>

// hash
struct FwdKey {
  u32 dip:32;
};
struct FwdLeaf {
  u32 fwd_idx:32;
};
BPF_TABLE("hash", struct FwdKey, struct FwdLeaf, fwd_map, 1);

// array
struct ConfigKey {
  u32 index;
};
struct ConfigLeaf {
  u32 bpfdev_ip;
  u32 slave_ip;
};
BPF_TABLE("array", struct ConfigKey, struct ConfigLeaf, config_map, 1);

// hash
struct MacaddrKey {
  u32 ip;
};
struct MacaddrLeaf {
  u64 mac;
};
BPF_TABLE("hash", struct MacaddrKey, struct MacaddrLeaf, macaddr_map, 11);

// hash
struct SlaveKey {
  u32 slave_ip;
};
struct SlaveLeaf {
  u32 slave_ifindex;
};
BPF_TABLE("hash", struct SlaveKey, struct SlaveLeaf, slave_map, 10);

int handle_packet(struct __sk_buff *skb) {
  int ret = 0;

  if (skb->pkt_type == 0) {
    // tx
    // make sure configured
    u32 slave_ip;

    struct ConfigKey cfg_key = {.index = 0};
    struct ConfigLeaf *cfg_leaf = config_map.lookup(&cfg_key);
    if (cfg_leaf) {
      slave_ip = cfg_leaf->slave_ip;
    } else {
      return 0xffffffff;
    }

    // make sure slave configured
    // tx, default to the single slave
    struct SlaveKey slave_key = {.slave_ip = slave_ip};
    struct SlaveLeaf *slave_leaf = slave_map.lookup(&slave_key);
    if (slave_leaf) {
      ret = slave_leaf->slave_ifindex;
    } else {
      return 0xffffffff;
    }
  } else {
    // rx, default to stack
    ret = 0;
  }

  BEGIN(ethernet);

  PROTO(ethernet) {
    switch (ethernet->type) {
      case 0x0806: goto arp;
      case 0x0800: goto ip;
      case 0x8100: goto dot1q;
    }
    goto EOP;
  }

  PROTO(dot1q) {
    switch (dot1q->type) {
      case 0x0806: goto arp;
      case 0x0800: goto ip;
    }
    goto EOP;
  }

  PROTO(arp) {
    if (skb->pkt_type) {
      if (arp->oper == 1) {
        struct MacaddrKey mac_key = {.ip=arp->spa};
        struct MacaddrLeaf mac_leaf = {.mac=arp->sha};
        macaddr_map.update(&mac_key, &mac_leaf);
      }
    }
    goto EOP;
  }

  PROTO(ip) {
    switch (ip->nextp) {
      case 6: goto tcp;
      case 17: goto udp;
    }
    goto EOP;
  }
  PROTO(tcp) {
    goto EOP;
  }
  PROTO(udp) {
    if (udp->dport != 5000) {
       goto EOP;
    }
    if (skb->pkt_type) {
      // lookup and then forward
      struct FwdKey fwd_key = {.dip=ip->dst};
      struct FwdLeaf *fwd_val = fwd_map.lookup(&fwd_key);
      if (fwd_val) {
         return fwd_val->fwd_idx;
      }
    } else {
      // rewrite the packet and send to a pre-configured index if needed
      u32 new_ip;
      u32 old_ip;
      u64 src_mac;
      u64 dst_mac;

      struct ConfigKey cfg_key = {.index = 0};
      struct ConfigLeaf *cfg_leaf = config_map.lookup(&cfg_key);
      if (cfg_leaf) {
        struct MacaddrKey mac_key = {.ip = cfg_leaf->bpfdev_ip};
        struct MacaddrLeaf *mac_leaf;

        mac_key.ip = cfg_leaf->bpfdev_ip;
        mac_leaf = macaddr_map.lookup(&mac_key);
        if (mac_leaf) {
          src_mac = mac_leaf->mac;
        } else {
          goto EOP;
        }

        mac_key.ip = cfg_leaf->slave_ip;
        mac_leaf = macaddr_map.lookup(&mac_key);
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

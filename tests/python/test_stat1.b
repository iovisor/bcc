// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")
struct IPKey {
  u32 dip:32;
  u32 sip:32;
};
struct IPLeaf {
  u32 rx_pkts:64;
  u32 tx_pkts:64;
};
Table<IPKey, IPLeaf, FIXED_MATCH, AUTO> stats(1024);

struct skbuff {
  u32 type:32;
};

u32 on_packet(struct skbuff *skb) {
  u32 ret:32 = 0;

  goto proto::ethernet;

  state proto::ethernet {
  }

  state proto::dot1q {
  }

  state proto::ip {
    u32 rx:32 = 0;
    u32 tx:32 = 0;
    u32 IPKey key;
    if $ip.dst > $ip.src {
      key.dip = $ip.dst;
      key.sip = $ip.src;
      rx = 1;
      // test arbitrary return stmt
      if false {
        return 3;
      }
    } else {
      key.dip = $ip.src;
      key.sip = $ip.dst;
      tx = 1;
      ret = 1;
    }
    struct IPLeaf *leaf;
    leaf = stats[key];
    on_valid(leaf) {
      atomic_add(leaf.rx_pkts, rx);
      atomic_add(leaf.tx_pkts, tx);
    }
  }

  state proto::udp {
  }

  state proto::vxlan {
  }

  state proto::gre {
  }

  state EOP {
    return ret;
  }
}

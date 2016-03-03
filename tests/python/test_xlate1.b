// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")
// test for packet modification

#packed "false"

struct IPKey {
  u32 dip:32;
  u32 sip:32;
};
struct IPLeaf {
  u32 xdip:32;
  u32 xsip:32;
  u64 xlated_pkts:64;
};
Table<IPKey, IPLeaf, FIXED_MATCH, NONE> xlate(1024);

struct skbuff {
  u32 type:32;
};

u32 on_packet (struct skbuff *skb) {
  u32 ret:32 = 1;

  u32 orig_dip:32 = 0;
  u32 orig_sip:32 = 0;
  struct IPLeaf *xleaf;

  goto proto::ethernet;

  state proto::ethernet {
  }

  state proto::dot1q {
  }

  state proto::ip {
    orig_dip = $ip.dst;
    orig_sip = $ip.src;
    struct IPKey key = {.dip=orig_dip, .sip=orig_sip};
    xlate.lookup(key, xleaf) {};
    on_valid(xleaf) {
      incr_cksum(@ip.hchecksum, orig_dip, xleaf.xdip);
      incr_cksum(@ip.hchecksum, orig_sip, xleaf.xsip);
      // the below are equivalent
      pkt.rewrite_field($ip.dst, xleaf.xdip);
      $ip.src = xleaf.xsip;
      atomic_add(xleaf.xlated_pkts, 1);
    }
  }

  state proto::udp {
    on_valid(xleaf) {
      incr_cksum(@udp.crc, orig_dip, xleaf.xdip, 1);
      incr_cksum(@udp.crc, orig_sip, xleaf.xsip, 1);
    }
  }

  state proto::tcp {
    on_valid(xleaf) {
      incr_cksum(@tcp.cksum, orig_dip, xleaf.xdip, 1);
      incr_cksum(@tcp.cksum, orig_sip, xleaf.xsip, 1);
    }
  }

  state proto::vxlan {
  }

  state proto::gre {
  }

  state EOP {
    return ret;
  }
}

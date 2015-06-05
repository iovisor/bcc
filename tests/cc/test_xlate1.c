#include "../../src/cc/bpf_helpers.h"
#include "../../src/cc/proto.h"
struct IPKey {
  u32 dip;
  u32 sip;
};
struct IPLeaf {
  u32 xdip;
  u32 xsip;
  u64 ip_xlated_pkts;
  u64 arp_xlated_pkts;
};
BPF_TABLE("hash", struct IPKey, struct IPLeaf, xlate, 1024);

BPF_EXPORT(on_packet)
int on_packet(struct __sk_buff *skb) {

  u32 orig_dip = 0;
  u32 orig_sip = 0;
  struct IPLeaf *xleaf;

  BEGIN(ethernet);
  PROTO(ethernet) {
    switch (ethernet->type) {
      case 0x0800: goto ip;
      case 0x0806: goto arp;
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
    orig_dip = arp->tpa;
    orig_sip = arp->spa;
    struct IPKey key = {.dip=orig_dip, .sip=orig_sip};
    xleaf = xlate.lookup(&key);
    if (xleaf) {
      arp->tpa = xleaf->xdip;
      arp->spa = xleaf->xsip;
      lock_xadd(&xleaf->arp_xlated_pkts, 1);
    }
    goto EOP;
  }

  PROTO(ip) {
    orig_dip = ip->dst;
    orig_sip = ip->src;
    struct IPKey key = {.dip=orig_dip, .sip=orig_sip};
    xleaf = xlate.lookup(&key);
    if (xleaf) {
      ip->dst = xleaf->xdip;
      incr_cksum_l3(&ip->hchecksum, orig_dip, xleaf->xdip);
      ip->src = xleaf->xsip;
      incr_cksum_l3(&ip->hchecksum, orig_sip, xleaf->xsip);
      lock_xadd(&xleaf->ip_xlated_pkts, 1);
    }
    switch (ip->nextp) {
      case 6: goto tcp;
      case 17: goto udp;
    }
    goto EOP;
  }

  PROTO(udp) {
    if (xleaf) {
      incr_cksum_l4(&udp->crc, orig_dip, xleaf->xdip, 1);
      incr_cksum_l4(&udp->crc, orig_sip, xleaf->xsip, 1);
    }
    goto EOP;
  }

  PROTO(tcp) {
    if (xleaf) {
      incr_cksum_l4(&tcp->cksum, orig_dip, xleaf->xdip, 1);
      incr_cksum_l4(&tcp->cksum, orig_sip, xleaf->xsip, 1);
    }
    goto EOP;
  }

EOP:
  return 1;
}

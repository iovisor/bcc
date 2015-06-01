#include "../../src/cc/bpf_helpers.h"
#include "../../src/cc/proto.h"

struct IPKey {
  u32 dip;
  u32 sip;
};
struct IPLeaf {
  u64 rx_pkts;
  u64 tx_pkts;
};

BPF_TABLE("hash", struct IPKey, struct IPLeaf, stats, 256);

BPF_EXPORT(on_packet)
int on_packet(struct __sk_buff *skb) {
  BEGIN(ethernet);

  PROTO(ethernet) {
    switch (ethernet->type) {
      case 0x0800: goto ip;
      case 0x8100: goto dot1q;
    }
  }
  PROTO(dot1q) {
    switch (dot1q->type) {
      case 0x0800: goto ip;
    }
  }
  PROTO(ip) {
    int rx = 0, tx = 0;
    struct IPKey key;
    if (ip->dst > ip->src) {
      key.dip = ip->dst;
      key.sip = ip->src;
      rx = 1;
    } else {
      key.dip = ip->src;
      key.sip = ip->dst;
      tx = 1;
    }
    struct IPLeaf zleaf = {0};
    struct IPLeaf *leaf = stats.lookup_or_init(&key, &zleaf);
    lock_xadd(&leaf->rx_pkts, rx);
    lock_xadd(&leaf->tx_pkts, tx);
  }
EOP:
  return 0;
}

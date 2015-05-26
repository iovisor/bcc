#include "../../src/cc/bpf_helpers.h"

struct IPKey {
  u32 dip;
  u32 sip;
};
struct IPLeaf {
  u64 rx_pkts;
  u64 tx_pkts;
};

BPF_TABLE("hash", struct IPKey, struct IPLeaf, stats, 256);

BPF_EXPORT(main)
int foo(struct __sk_buff *skb) {
  size_t next = 0, cur = 0;
ethernet:
{
  cur = next; next += 14;

  switch (bpf_dext_pkt(skb, cur + 12, 0, 16)) {
    case 0x800: goto ip;
    case 0x8100: goto dot1q;
    default: goto EOP;
  }
}
dot1q:
{
  cur = next; next += 4;

  switch (bpf_dext_pkt(skb, cur + 2, 0, 16)) {
    case 0x0800: goto ip;
    default: goto EOP;
  }
}

ip:
{
  cur = next; next += 20;

  int rx = 0;
  int tx = 0;
  struct IPKey key = {0};
  if (bpf_dext_pkt(skb, cur + 16, 0, 32) > bpf_dext_pkt(skb, cur + 12, 0, 32)) {
    key.sip = bpf_dext_pkt(skb, cur + 12, 0, 32);
    key.dip = bpf_dext_pkt(skb, cur + 16, 0, 32);
    rx = 1;
  } else {
    key.dip = bpf_dext_pkt(skb, cur + 12, 0, 32);
    key.sip = bpf_dext_pkt(skb, cur + 16, 0, 32);
    tx = 1;
  }
  // try to get here:
  //stats[key].rx_pkts += rx;
  //stats[key].tx_pkts += tx;
  // or here:
  //struct IPLeaf *leaf = stats[key];
  //if (leaf) {
  //  __sync_fetch_and_add(&leaf->rx_pkts, rx);
  //  __sync_fetch_and_add(&leaf->tx_pkts, tx);
  //}
  struct IPLeaf *leaf;
  leaf = stats.get(&key);
  if (!leaf) {
    struct IPLeaf zleaf = {0};
    stats.put(&key, &zleaf);
    leaf = stats.get(&key);
  }
  if (leaf) {
    __sync_fetch_and_add(&leaf->rx_pkts, rx);
    __sync_fetch_and_add(&leaf->tx_pkts, tx);
  }

  switch (bpf_dext_pkt(skb, cur + 9, 0, 8)) {
    case 6: goto tcp;
    case 17: goto udp;
    //case 47: goto gre;
    default: goto EOP;
  }
}

udp:
{
  cur = next; next += 8;

  switch (bpf_dext_pkt(skb, cur + 2, 0, 16)) {
    //case 8472: goto vxlan;
    //case 4789: goto vxlan;
    default: goto EOP;
  }
}

tcp:
{
  cur = next; next += 20;

  goto EOP;
}

EOP:
  return 0;
}

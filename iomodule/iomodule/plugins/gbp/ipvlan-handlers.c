#include <bcc/proto.h>

struct in6addr {
  uint64_t low;
  uint64_t high;
};
struct ip6_t {
  unsigned int    ver:4;           // byte 0
  unsigned int    class:8;
  unsigned int    flow_label:20;

  unsigned short  len;             // byte 4
  unsigned char   next_header;  
  unsigned char   hop_limit;

  struct in6addr  src;             // byte 8

  struct in6addr  dst;             // byte 20
} BPF_PACKET_HEADER;

typedef struct {
  u32 ip4;
  char is_ipv6;
  char pad[3];
} IPKey;
BPF_TABLE("hash", IPKey, uint16_t, ip2grp, 1024);

typedef struct {
  uint16_t src_tag;
  uint16_t dst_tag;
} GroupKey;

enum {
  ACTION_DROP,
  ACTION_PASS,
  ACTION_TAP,
};
typedef struct {
  int action;
  uint64_t rx_pkts;
  uint64_t rx_bytes;
} Policy;
BPF_TABLE("hash", GroupKey, Policy, grp2policy, 1024);

int ingress(struct __sk_buff *skb) {
  //bpf_trace_printk("ingress: %d\n", skb->ifindex);
  u8 *cursor = 0;
  IPKey ipkey = {};
  u16 src_tag = skb->tc_index;

  ethernet: {
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    uint16_t ethertype = ethernet->type;
    switch (ethertype) {
      case ETH_P_IP: goto ip;
      case ETH_P_IPV6: goto ipv6;
      case ETH_P_ARP: goto arp;
      default:
        bpf_trace_printk("invalid ethernet type %u\n", ethertype);
        return 2;
    }
  }

  ip: {
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    ipkey.ip4 = ip->dst;
    goto EOP;
  }

  ipv6: {
    //struct ip6_t *ip6 = cursor_advance(cursor, sizeof(*ip));
    //memcpy(&ipkey.ip, &ip6->
    //ipkey.is_ipv6 = 1;
    goto EOP;
  }

  arp: {
    return 0;
  }

EOP: ;
  uint16_t *dst_tag = ip2grp.lookup(&ipkey);
  if (!dst_tag) {
    bpf_trace_printk("group lookup failed for 0x%x\n", ipkey.ip4);
    return 2;
  }
  GroupKey grpkey = {.src_tag = src_tag, .dst_tag = *dst_tag};
  Policy *policy = grp2policy.lookup(&grpkey);
  if (!policy) {
    bpf_trace_printk("policy lookup failed for (%u, %u)\n", grpkey.src_tag, grpkey.dst_tag);
    return 2;
  }
  policy->rx_pkts++;
  policy->rx_bytes += skb->len;
  if (policy->action == ACTION_PASS)
    return 0;
  bpf_trace_printk("policy action DROP for (%u, %u)\n", grpkey.src_tag, grpkey.dst_tag);
  return 2;
}

int egress(struct __sk_buff *skb) {
  //bpf_trace_printk("egress: %d\n", skb->ifindex);
  u8 *cursor = 0;
  IPKey ipkey = {};

  ethernet: {
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    switch (ethernet->type) {
      case ETH_P_IP: goto ip;
      case ETH_P_IPV6: goto ipv6;
      case ETH_P_ARP: goto arp;
      default: return 2;
    }
  }

  ip: {
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    if ((0xffff0000 & ip->dst) != 0x0a010000)
      return 0;
    ipkey.ip4 = ip->src;
  }

  ipv6: {
    //struct ip6_t *ip6 = cursor_advance(cursor, sizeof(*ip));
    //memcpy(&ipkey.ip, 
    //ipkey.is_ipv6 = 1;
    goto EOP;
  }

  arp: {
    return 0;
  }

EOP: ;
  uint16_t *src_tag = ip2grp.lookup(&ipkey);
  if (!src_tag) {
    bpf_trace_printk("ip2grp mapping not found\n");
    return 0;
  }
  skb->tc_index = *src_tag;
  return 0;
}

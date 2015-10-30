#include <bcc/proto.h>

int ingress(struct __sk_buff *skb) {
  //bpf_trace_printk("ingress: %d\n", skb->ifindex);
  u8 *cursor = 0;

  ethernet: {
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    if (skb->vlan_present) {
      skb->tc_index = skb->vlan_tci & 0xfff;
      bpf_skb_vlan_pop(skb);
      //bpf_trace_printk("ingress: %d %d %d\n", skb->ifindex, skb->tc_index);
      //bpf_trace_printk("ingress: protocol %x\n", skb->protocol);
    }
    uint16_t ethertype = ethernet->type;
    switch (ethertype) {
      default: goto EOP;
    }
  }

EOP: ;
  return 100;
}

int egress(struct __sk_buff *skb) {
  //bpf_trace_printk("egress: %d\n", skb->ifindex);
  u8 *cursor = 0;
  uint16_t src_tag = skb->tc_index;

  ethernet: {
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    uint16_t ethertype = ethernet->type;
    if (src_tag)
      bpf_skb_vlan_push(skb, ethertype, src_tag);
    switch (ethertype) {
      default: goto EOP;
    }
  }

EOP: ;
  return 0;
}

#include <bcc/proto.h>
#include <uapi/linux/pkt_cls.h>

// extern
// supports 32K "links"
BPF_TABLE("prog", int, int, forward, 65536);

static int ifc_send(struct __sk_buff *skb, int out) {
  //bpf_trace_printk("patch: ifc_send %p %d\n", skb, out);
  if (out < 0) {
    out = -out;
    // ports are programmed in the table in odd/even pairs
    skb->cb[0] = -(out ^ 1);
    forward.call(skb, out);
  } else {
    bpf_clone_redirect(skb, out, 0);
  }
  return TC_ACT_SHOT;
}

BPF_TABLE("hash", int, int, patch, 1024);

int recv_netdev(struct __sk_buff *skb) {
  int in = skb->ifindex;
  //bpf_trace_printk("recv_netdev: in %p %d\n", skb, in);
  int *out = patch.lookup(&in);
  if (out)
    return ifc_send(skb, *out);
  bpf_trace_printk("recv_netdev: no out for in %p %d\n", skb, in);
  return TC_ACT_SHOT;
}

int recv_tailcall(struct __sk_buff *skb) {
  int in = skb->cb[0];
  if (!in)
    return TC_ACT_SHOT;

  //bpf_trace_printk("recv_tailcall: in %p %d\n", skb, in);
  int *out = patch.lookup(&in);
  if (out)
    return ifc_send(skb, *out);
  bpf_trace_printk("recv_tailcall: no out for in %p %d\n", skb, in);
  return TC_ACT_SHOT;
}

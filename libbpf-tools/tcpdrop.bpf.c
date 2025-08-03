#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "tcpdrop.h"

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86dd
#endif

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 512);
} events SEC(".maps");

#define MAX_STACK_DEPTH 15
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 512);
	__uint(key_size, sizeof(u32));
	__uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} stack_traces SEC(".maps");

const volatile char ipv4_only = 0;
const volatile char ipv6_only = 0;
const volatile __u32 netns_id = 0;

SEC("tracepoint/skb/kfree_skb")
int tp__skb_free_skb(struct trace_event_raw_kfree_skb *args)
{
	struct sk_buff *skb;
	struct sock *sk;
	void *head;
	u16 network_header, transport_header, protocol;
	u64 pid_tgid;
	u32 pid;
	struct net *net;
	u32 inum;
	u8 state;
	struct iphdr ip;
	struct ipv6hdr ip6;
	struct tcphdr tcp;
	struct event *event;

	skb = args->skbaddr;
	if (!skb)
		return 0;

	if (bpf_core_field_exists(args->reason))
		if (args->reason <= SKB_DROP_REASON_NOT_SPECIFIED)
			return 0;

	protocol = args->protocol;
	if (protocol != ETH_P_IP && protocol != ETH_P_IPV6)
		return 0;
	if (ipv4_only && protocol != ETH_P_IP)
		return 0;
	if (ipv6_only && protocol != ETH_P_IPV6)
		return 0;

	bpf_core_read(&sk, sizeof(sk), &skb->sk);

	if (netns_id && sk) {
		net = NULL;
		bpf_core_read(&net, sizeof(net), &sk->__sk_common.skc_net.net);
		if (net) {
			bpf_core_read(&inum, sizeof(inum), &net->ns.inum);
			if (inum != netns_id)
				return 0;
		}
	}

	if (bpf_core_read(&head, sizeof(head), &skb->head) ||
	    bpf_core_read(&network_header, sizeof(network_header),
			  &skb->network_header) ||
	    bpf_core_read(&transport_header, sizeof(transport_header),
			  &skb->transport_header))
		return 0;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	if (protocol == ETH_P_IP) {
		if (bpf_core_read(&ip, sizeof(ip), head + network_header) ||
		    ip.protocol != IPPROTO_TCP ||
		    bpf_core_read(&tcp, sizeof(tcp), head + transport_header)) {
			bpf_ringbuf_discard(event, 0);
			return 0;
		}
		event->ip_version = 4;
		event->saddr_v4 = ip.saddr;
		event->daddr_v4 = ip.daddr;
		event->sport = bpf_ntohs(tcp.source);
		event->dport = bpf_ntohs(tcp.dest);
		event->tcpflags = ((u8 *)&tcp)[13];
	} else {
		if (bpf_core_read(&ip6, sizeof(ip6), head + network_header) ||
		    ip6.nexthdr != IPPROTO_TCP ||
		    bpf_core_read(&tcp, sizeof(tcp), head + transport_header)) {
			bpf_ringbuf_discard(event, 0);
			return 0;
		}
		event->ip_version = 6;
		bpf_core_read(&event->saddr_v6, sizeof(event->saddr_v6),
			      &ip6.saddr.in6_u.u6_addr32);
		bpf_core_read(&event->daddr_v6, sizeof(event->daddr_v6),
			      &ip6.daddr.in6_u.u6_addr32);
		event->sport = bpf_ntohs(tcp.source);
		event->dport = bpf_ntohs(tcp.dest);
		event->tcpflags = ((u8 *)&tcp)[13];
	}

	if (bpf_core_field_exists(args->reason))
		event->drop_reason = args->reason;
	else
		event->drop_reason = -1;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	event->timestamp = bpf_ktime_get_ns();
	event->pid = pid;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	event->stack_id = bpf_get_stackid(args, &stack_traces, 0);
	event->state = 127;
	if (sk)
		if (!bpf_core_read(&state, sizeof(state),
				   &sk->__sk_common.skc_state))
			event->state = state;

	bpf_ringbuf_submit(event, 0);
	return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86dd
#endif

struct event {
    u64 timestamp;
    u32 pid;
    u32 drop_reason;
    u32 ip_version; // 4 for IPv4, 6 for IPv6
    union {
        u32 saddr_v4;
        unsigned __int128 saddr_v6;
    };
    union {
        u32 daddr_v4;
        unsigned __int128 daddr_v6;
    };
    u16 sport;
    u16 dport;
    u8 state;
    u8 tcpflags;
    char comm[TASK_COMM_LEN];
    u32 stack_id;
};

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

char ipv4_only = 0;
char ipv6_only = 0;
__u32 netns_id = 0;

SEC("tracepoint/skb/kfree_skb")
int tp__skb_free_skb(struct trace_event_raw_kfree_skb *args)
{
    if (args->reason <= SKB_DROP_REASON_NOT_SPECIFIED) {
        return 0;
    }

    if (bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA) >= 511) {
        bpf_printk("Ring buffer is almost full\n");
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    struct sk_buff *skb = args->skbaddr;
    if (!skb) {
        return 0;
    }
    struct sock *sk = NULL;
    bpf_core_read(&sk, sizeof(sk), &skb->sk);

    // Get packet headers
    void *head;
    u16 network_header, transport_header;
    if (bpf_core_read(&head, sizeof(head), &skb->head) ||
        bpf_core_read(&network_header, sizeof(network_header), &skb->network_header) ||
        bpf_core_read(&transport_header, sizeof(transport_header), &skb->transport_header)) {
        bpf_printk("Failed to read skb headers\n");
        return 0;
    }

    // Check protocol and filter by IP family
    u16 protocol = args->protocol;
    if (protocol != ETH_P_IP && protocol != ETH_P_IPV6) {
        bpf_printk("Unsupported protocol: %u\n", protocol);
        return 0;
    }
    if (ipv4_only && protocol != ETH_P_IP) {
        return 0;
    }
    if (ipv6_only && protocol != ETH_P_IPV6) {
        return 0;
    }

    // Filter by network namespace
    if (netns_id && sk) {
        struct net *net = NULL;
        bpf_core_read(&net, sizeof(net), &sk->__sk_common.skc_net.net);
        if (net) {
            u32 inum;
            bpf_core_read(&inum, sizeof(inum), &net->ns.inum);
            if (inum != netns_id) {
                bpf_printk("Skipping packet from different netns: %u != %u\n", inum, netns_id);
                return 0;
            }
        }
    }

    struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->drop_reason = args->reason;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->stack_id = bpf_get_stackid(args, &stack_traces, 0);
    event->state = 127;
    if (sk) {
        u8 state;
        if (!bpf_core_read(&state, sizeof(state), &sk->__sk_common.skc_state)) {
            event->state = state;
        }
    }

    if (protocol == ETH_P_IP) {
        struct iphdr ip;
        if (bpf_core_read(&ip, sizeof(ip), head + network_header)) {
            bpf_ringbuf_discard(event, 0);
            return 0;
        }
        if (ip.protocol != IPPROTO_TCP) {
            bpf_ringbuf_discard(event, 0);
            return 0;
        }
        struct tcphdr tcp;
        if (bpf_core_read(&tcp, sizeof(tcp), head + transport_header)) {
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
        struct ipv6hdr ip6;
        if (bpf_core_read(&ip6, sizeof(ip6), head + network_header)) {
            bpf_ringbuf_discard(event, 0);
            return 0;
        }
        if (ip6.nexthdr != IPPROTO_TCP) {
            bpf_ringbuf_discard(event, 0);
            return 0;
        }
        struct tcphdr tcp;
        if (bpf_core_read(&tcp, sizeof(tcp), head + transport_header)) {
            bpf_ringbuf_discard(event, 0);
            return 0;
        }
        event->ip_version = 6;
        bpf_core_read(&event->saddr_v6, sizeof(event->saddr_v6), &ip6.saddr);
        bpf_core_read(&event->daddr_v6, sizeof(event->daddr_v6), &ip6.daddr);
        event->sport = bpf_ntohs(tcp.source);
        event->dport = bpf_ntohs(tcp.dest);
        event->tcpflags = ((u8 *)&tcp)[13];
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
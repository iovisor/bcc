// SPDX-License-Identifier: GPL-2.0

/*
 * tcpretrans  Trace IPv4 and IPv6 tcp retransmit events
 *
 * Copyright (c) 2020 Anton Protopopov
 * Copyright (c) 2021 Red Hat, Inc.
 *
 * Based on tcpconnect.c by Anton Protopopov and
 * tcpretrans(8) from BCC by Brendan Gregg
 * 15-Jul-2021   Michael Gugino   Created this.
 */
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "maps.bpf.h"
#include "tcpretrans.h"

/* Define here, because there are conflicts with include files */
#define AF_INET		2
#define AF_INET6	10

const volatile bool do_count = false;

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct ipv4_flow_key);
	__type(value, u64);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} ipv4_count SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct ipv6_flow_key);
	__type(value, u64);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} ipv6_count SEC(".maps");

static void count_v4(const struct sock *skp)
{
	struct ipv4_flow_key key;
	static const __u64 zero;
	__u64 *val;

	BPF_CORE_READ_INTO(&key.saddr, skp, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&key.daddr, skp, __sk_common.skc_daddr);
	BPF_CORE_READ_INTO(&key.dport, skp, __sk_common.skc_dport);
	BPF_CORE_READ_INTO(&key.sport, skp, __sk_common.skc_num);
	val = bpf_map_lookup_or_try_init(&ipv4_count, &key, &zero);
	if (val)
		__atomic_add_fetch(val, 1, __ATOMIC_RELAXED);
}

static void count_v6(const struct sock *skp)
{
	struct ipv6_flow_key key;
	static const __u64 zero;
	__u64 *val;

	BPF_CORE_READ_INTO(&key.saddr, skp,
			   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	BPF_CORE_READ_INTO(&key.daddr, skp,
			   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	BPF_CORE_READ_INTO(&key.dport, skp, __sk_common.skc_dport);
	BPF_CORE_READ_INTO(&key.sport, skp, __sk_common.skc_num);

	val = bpf_map_lookup_or_try_init(&ipv6_count, &key, &zero);
	if (val)
		__atomic_add_fetch(val, 1, __ATOMIC_RELAXED);
}

static int trace_event(void *ctx, const struct sock *skp, int type)
{
	struct event e = {};
	__u32 family;
	__u64 pid_tgid;
	__u32 pid;
	int state;

	if (skp == NULL)
		return 0;

	family = BPF_CORE_READ(skp, __sk_common.skc_family);
	e.af = family;

	if (do_count) {
		if (family == AF_INET)
			count_v4(skp);
		else
			count_v6(skp);
		return 0;
	}

	e.type = type;
	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	e.pid = pid;

	BPF_CORE_READ_INTO(&e.dport, skp, __sk_common.skc_dport);
	BPF_CORE_READ_INTO(&e.sport, skp, __sk_common.skc_num);
	e.state = BPF_CORE_READ(skp, __sk_common.skc_state);

	if (family == AF_INET) {
		BPF_CORE_READ_INTO(&e.saddr, skp, __sk_common.skc_rcv_saddr);
		BPF_CORE_READ_INTO(&e.daddr, skp, __sk_common.skc_daddr);
	} else if (family == AF_INET6) {
		BPF_CORE_READ_INTO(&e.saddr, skp,
				   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&e.daddr, skp,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
	return 0;
}

SEC("tp/tcp/tcp_retransmit_skb")
int tp_tcp_retransmit_skb(struct trace_event_raw_tcp_event_sk_skb *ctx)
{
	const struct sock *skp;

	skp = BPF_CORE_READ(ctx, skaddr);
	return trace_event(ctx, skp, RETRANSMIT);
}

SEC("kprobe/tcp_send_loss_probe")
int BPF_KPROBE(tcp_send_loss_probe, struct sock *sk)
{
	return trace_event(ctx, sk, TLP);
}

SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(tcp_retransmit_skb, struct sock *sk)
{
	return trace_event(ctx, sk, RETRANSMIT);
}

char LICENSE[] SEC("license") = "GPL";
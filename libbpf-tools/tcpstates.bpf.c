// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tcpstates.h"

#define MAX_ENTRIES	10240
#define AF_INET		2
#define AF_INET6	10

const volatile bool filter_by_sport = false;
const volatile bool filter_by_dport = false;
const volatile short target_family = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u16);
	__type(value, __u16);
} sports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u16);
	__type(value, __u16);
} dports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct sock *);
	__type(value, __u64);
} timestamps SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

static inline int tcp_sock_create(struct sock *sk)
{
	__u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&timestamps, &sk, &ts, BPF_ANY);
	return 0;
}

SEC("kprobe/tcp_v4_init_sock")
int BPF_KPROBE(tcp_v4_init_sock, struct sock *sk)
{
	return tcp_sock_create(sk);
}

SEC("kprobe/tcp_v6_init_sock")
int BPF_KPROBE(tcp_v6_init_sock, struct sock *sk)
{
	return tcp_sock_create(sk);
}

SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	struct sock *sk = (struct sock *)ctx->skaddr;
	__u16 family = ctx->family;
	__u16 sport = ctx->sport;
	__u16 dport = ctx->dport;
	__u64 *tsp, delta_ns, ts;
	struct event event = {};

	if (ctx->protocol != IPPROTO_TCP)
		return 0;

	if (target_family && target_family != family)
		return 0;

	if (filter_by_sport && !bpf_map_lookup_elem(&sports, &sport))
		return 0;

	if (filter_by_dport && !bpf_map_lookup_elem(&dports, &dport))
		return 0;

	tsp = bpf_map_lookup_elem(&timestamps, &sk);
	ts = bpf_ktime_get_ns();
	if (!tsp)
		delta_ns = 0;
	else
		delta_ns = (ts - *tsp);

	event.skaddr = (__u64)sk;
	event.ts_us = ts / 1000;
	event.delta_ns = delta_ns;
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.oldstate = ctx->oldstate;
	event.newstate = ctx->newstate;
	event.family = family;
	event.sport = sport;
	event.dport = dport;
	bpf_get_current_comm(&event.task, sizeof(event.task));

	if (family == AF_INET) {
		bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_rcv_saddr);
		bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_daddr);
	} else { /* family == AF_INET6 */
		bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	if (ctx->newstate == TCP_CLOSE)
		bpf_map_delete_elem(&timestamps, &sk);
	else
		bpf_map_update_elem(&timestamps, &sk, &ts, BPF_ANY);

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

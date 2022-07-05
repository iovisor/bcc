// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "tcplife.h"

#define MAX_ENTRIES	10240
#define AF_INET		2
#define AF_INET6	10

const volatile bool filter_sport = false;
const volatile bool filter_dport = false;
const volatile __u16 target_sports[MAX_PORTS] = {};
const volatile __u16 target_dports[MAX_PORTS] = {};
const volatile pid_t target_pid = 0;
const volatile __u16 target_family = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct sock *);
	__type(value, __u64);
} birth SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct sock *);
	__type(value, struct ident);
} idents SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *args)
{
	__u64 ts, *start, delta_us, rx_b, tx_b;
	struct ident ident = {}, *identp;
	__u16 sport, dport, family;
	struct event event = {};
	struct tcp_sock *tp;
	struct sock *sk;
	bool found;
	__u32 pid;
	int i;

	if (BPF_CORE_READ(args, protocol) != IPPROTO_TCP)
		return 0;

	family = BPF_CORE_READ(args, family);
	if (target_family && family != target_family)
		return 0;

	sport = BPF_CORE_READ(args, sport);
	if (filter_sport) {
		found = false;
		for (i = 0; i < MAX_PORTS; i++) {
			if (!target_sports[i])
				return 0;
			if (sport != target_sports[i])
				continue;
			found = true;
			break;
		}
		if (!found)
			return 0;
	}

	dport = BPF_CORE_READ(args, dport);
	if (filter_dport) {
		found = false;
		for (i = 0; i < MAX_PORTS; i++) {
			if (!target_dports[i])
				return 0;
			if (dport != target_dports[i])
				continue;
			found = true;
			break;
		}
		if (!found)
			return 0;
	}

	sk = (struct sock *)BPF_CORE_READ(args, skaddr);
	if (BPF_CORE_READ(args, newstate) < TCP_FIN_WAIT1) {
		ts = bpf_ktime_get_ns();
		bpf_map_update_elem(&birth, &sk, &ts, BPF_ANY);
	}

	if (BPF_CORE_READ(args, newstate) == TCP_SYN_SENT || BPF_CORE_READ(args, newstate) == TCP_LAST_ACK) {
		pid = bpf_get_current_pid_tgid() >> 32;
		if (target_pid && pid != target_pid)
			return 0;
		ident.pid = pid;
		bpf_get_current_comm(ident.comm, sizeof(ident.comm));
		bpf_map_update_elem(&idents, &sk, &ident, BPF_ANY);
	}

	if (BPF_CORE_READ(args, newstate) != TCP_CLOSE)
		return 0;

	start = bpf_map_lookup_elem(&birth, &sk);
	if (!start) {
		bpf_map_delete_elem(&idents, &sk);
		return 0;
	}
	ts = bpf_ktime_get_ns();
	delta_us = (ts - *start) / 1000;

	identp = bpf_map_lookup_elem(&idents, &sk);
	pid = identp ? identp->pid : bpf_get_current_pid_tgid() >> 32;
	if (target_pid && pid != target_pid)
		goto cleanup;

	tp = (struct tcp_sock *)sk;
	rx_b = BPF_CORE_READ(tp, bytes_received);
	tx_b = BPF_CORE_READ(tp, bytes_acked);

	event.ts_us = ts / 1000;
	event.span_us = delta_us;
	event.rx_b = rx_b;
	event.tx_b = tx_b;
	event.pid = pid;
	event.sport = sport;
	event.dport = dport;
	event.family = family;
	if (!identp)
		bpf_get_current_comm(event.comm, sizeof(event.comm));
	else
		bpf_probe_read_kernel(event.comm, sizeof(event.comm), (void *)identp->comm);
	if (family == AF_INET) {
		bpf_probe_read_kernel(&event.saddr, sizeof(args->saddr), BPF_CORE_READ(args, saddr));
		bpf_probe_read_kernel(&event.daddr, sizeof(args->daddr), BPF_CORE_READ(args, daddr));
	} else {	/*  AF_INET6 */
		bpf_probe_read_kernel(&event.saddr, sizeof(args->saddr_v6), BPF_CORE_READ(args, saddr_v6));
		bpf_probe_read_kernel(&event.daddr, sizeof(args->daddr_v6), BPF_CORE_READ(args, daddr_v6));
	}
	bpf_perf_event_output(args, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

cleanup:
	bpf_map_delete_elem(&birth, &sk);
	bpf_map_delete_elem(&idents, &sk);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

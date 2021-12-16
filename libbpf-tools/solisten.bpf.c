/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "solisten.h"

#define MAX_ENTRIES	10240
#define AF_INET	2
#define AF_INET6	10

const volatile pid_t target_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct event);
} values SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

static void fill_event(struct event *event, struct socket *sock)
{
	__u16 family, type;
	struct sock *sk;
	struct inet_sock *inet;

	sk = BPF_CORE_READ(sock, sk);
	inet = (struct inet_sock *)sk;
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	type = BPF_CORE_READ(sock, type);

	event->proto = ((__u32)family << 16) | type;
	event->port = bpf_ntohs(BPF_CORE_READ(inet, inet_sport));
	if (family == AF_INET)
		event->addr[0] = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	else if (family == AF_INET6)
		BPF_CORE_READ_INTO(event->addr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	bpf_get_current_comm(event->task, sizeof(event->task));
}

SEC("kprobe/inet_listen")
int BPF_KPROBE(inet_listen_entry, struct socket *sock, int backlog)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct event event = {};

	if (target_pid && target_pid != pid)
		return 0;

	fill_event(&event, sock);
	event.pid = pid;
	event.backlog = backlog;
	bpf_map_update_elem(&values, &tid, &event, BPF_ANY);
	return 0;
}

SEC("kretprobe/inet_listen")
int BPF_KRETPROBE(inet_listen_exit, int ret)
{
	__u32 tid = bpf_get_current_pid_tgid();
	struct event *eventp;

	eventp = bpf_map_lookup_elem(&values, &tid);
	if (!eventp)
		return 0;

	eventp->ret = ret;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, eventp, sizeof(*eventp));
	bpf_map_delete_elem(&values, &tid);
	return 0;
}

SEC("fexit/inet_listen")
int BPF_PROG(inet_listen_fexit, struct socket *sock, int backlog, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	struct event event = {};

	if (target_pid && target_pid != pid)
		return 0;

	fill_event(&event, sock);
	event.pid = pid;
	event.backlog = backlog;
	event.ret = ret;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

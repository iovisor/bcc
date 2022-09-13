// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "tcpaccept.h"

#define AF_INET		2
#define AF_INET6	10
#define MAX_PORTS	1024

const volatile pid_t target_pid = -1;
const volatile int target_family = -1;
const volatile bool filter_by_port = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PORTS);
	__type(key, __u16);
	__type(value, __u16);
} ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept, struct sock *newsk)
{
	__u16 proto, family, lport, *port;
	struct event event = {};
	__u32 pid;

	if (!newsk)
		return 0;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (target_pid != -1 && pid != target_pid)
		return 0;

	proto = BPF_CORE_READ_BITFIELD_PROBED(newsk, sk_protocol);
	if (proto != IPPROTO_TCP)
		return 0;

	family = BPF_CORE_READ(newsk, __sk_common.skc_family);
	if (target_family != -1 && family != target_family)
		return 0;

	lport = BPF_CORE_READ(newsk, __sk_common.skc_num);
	port = bpf_map_lookup_elem(&ports, &lport);
	if (filter_by_port && !port)
		return 0;

	event.ts_us = bpf_ktime_get_ns() / 1000;
	event.pid = pid;
	event.lport = lport;
	event.dport = bpf_ntohs(BPF_CORE_READ(newsk, __sk_common.skc_dport));
	bpf_get_current_comm(&event.task, sizeof(event.task));
	if (family == AF_INET) {
		event.saddr = BPF_CORE_READ(newsk, __sk_common.skc_rcv_saddr);
		event.daddr = BPF_CORE_READ(newsk, __sk_common.skc_daddr);
		event.family = 4;
	} else if (family == AF_INET6) {
		bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr),
				      newsk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr),
				      newsk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
		event.family = 6;
	}
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

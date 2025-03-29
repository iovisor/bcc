// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Microsoft Corporation
//
// Based on tcptracer(8) from BCC by Kinvolk GmbH and
// tcpconnect(8) by Anton Protopopov
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "tcptracer.h"

const volatile uid_t filter_uid = -1;
const volatile pid_t filter_pid = 0;

/* Define here, because there are conflicts with include files */
#define AF_INET		2
#define AF_INET6	10

/*
 * tcp_set_state doesn't run in the context of the process that initiated the
 * connection so we need to store a map TUPLE -> PID to send the right PID on
 * the event.
 */
struct tuple_key_t {
	union {
		__u32 saddr_v4;
		unsigned __int128 saddr_v6;
	};
	union {
		__u32 daddr_v4;
		unsigned __int128 daddr_v6;
	};
	u16 sport;
	u16 dport;
	u32 netns;
};

struct pid_comm_t {
	u64 pid;
	char comm[TASK_COMM_LEN];
	u32 uid;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct tuple_key_t);
	__type(value, struct pid_comm_t);
} tuplepid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct sock *);
} sockets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");


static __always_inline bool
fill_tuple(struct tuple_key_t *tuple, struct sock *sk, int family)
{
	struct inet_sock *sockp = (struct inet_sock *)sk;

	BPF_CORE_READ_INTO(&tuple->netns, sk, __sk_common.skc_net.net, ns.inum);

	switch (family) {
	case AF_INET:
		BPF_CORE_READ_INTO(&tuple->saddr_v4, sk, __sk_common.skc_rcv_saddr);
		if (tuple->saddr_v4 == 0)
			return false;

		BPF_CORE_READ_INTO(&tuple->daddr_v4, sk, __sk_common.skc_daddr);
		if (tuple->daddr_v4 == 0)
			return false;

		break;
	case AF_INET6:
		BPF_CORE_READ_INTO(&tuple->saddr_v6, sk,
				   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		if (tuple->saddr_v6 == 0)
			return false;
		BPF_CORE_READ_INTO(&tuple->daddr_v6, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
		if (tuple->daddr_v6 == 0)
			return false;

		break;
	/* it should not happen but to be sure let's handle this case */
	default:
		return false;
	}

	BPF_CORE_READ_INTO(&tuple->dport, sk, __sk_common.skc_dport);
	if (tuple->dport == 0)
		return false;

	BPF_CORE_READ_INTO(&tuple->sport, sockp, inet_sport);
	if (tuple->sport == 0)
		return false;

	return true;
}

static __always_inline void
fill_event(struct tuple_key_t *tuple, struct event *event, __u32 pid,
	   __u32 uid, __u16 family, __u8 type)
{
	event->ts_us = bpf_ktime_get_ns() / 1000;
	event->type = type;
	event->pid = pid;
	event->uid = uid;
	event->af = family;
	event->netns = tuple->netns;
	if (family == AF_INET) {
		event->saddr_v4 = tuple->saddr_v4;
		event->daddr_v4 = tuple->daddr_v4;
	} else {
		event->saddr_v6 = tuple->saddr_v6;
		event->daddr_v6 = tuple->daddr_v6;
	}
	event->sport = tuple->sport;
	event->dport = tuple->dport;
}

/* returns true if the event should be skipped */
static __always_inline bool
filter_event(struct sock *sk, __u32 uid, __u32 pid)
{
	u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

	if (family != AF_INET && family != AF_INET6)
		return true;

	if (filter_pid && pid != filter_pid)
		return true;

	if (filter_uid != (uid_t) -1 && uid != filter_uid)
		return true;

	return false;
}

static __always_inline int
enter_tcp_connect(struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = pid_tgid;
	__u64 uid_gid = bpf_get_current_uid_gid();
	__u32 uid = uid_gid;

	if (filter_event(sk, uid, pid))
		return 0;

	bpf_map_update_elem(&sockets, &tid, &sk, 0);
	return 0;
}

static __always_inline int
exit_tcp_connect(int ret, __u16 family)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = pid_tgid;
	__u64 uid_gid = bpf_get_current_uid_gid();
	__u32 uid = uid_gid;
	struct tuple_key_t tuple = {};
	struct pid_comm_t pid_comm = {};
	struct sock **skpp;
	struct sock *sk;

	skpp = bpf_map_lookup_elem(&sockets, &tid);
	if (!skpp)
		return 0;

	if (ret)
		goto end;

	sk = *skpp;

	if (!fill_tuple(&tuple, sk, family))
		goto end;

	pid_comm.pid = pid;
	pid_comm.uid = uid;
	bpf_get_current_comm(&pid_comm.comm, sizeof(pid_comm.comm));

	bpf_map_update_elem(&tuplepid, &tuple, &pid_comm, 0);

end:
	bpf_map_delete_elem(&sockets, &tid);
	return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
	return enter_tcp_connect(sk);
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_ret, int ret)
{
	return exit_tcp_connect(ret, AF_INET);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tcp_v6_connect, struct sock *sk)
{
	return enter_tcp_connect(sk);
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(tcp_v6_connect_ret, int ret)
{
	return exit_tcp_connect(ret, AF_INET6);
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(entry_trace_close, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u64 uid_gid = bpf_get_current_uid_gid();
	__u32 uid = uid_gid;
	struct tuple_key_t tuple = {};
	struct event event = {};
	u16 family;

	if (filter_event(sk, uid, pid))
		return 0;

	/*
	 * Don't generate close events for connections that were never
	 * established in the first place.
	 */
	u8 oldstate = BPF_CORE_READ(sk, __sk_common.skc_state);
	if (oldstate == TCP_SYN_SENT ||
	    oldstate == TCP_SYN_RECV ||
	    oldstate == TCP_NEW_SYN_RECV)
		return 0;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (!fill_tuple(&tuple, sk, family))
		return 0;

	fill_event(&tuple, &event, pid, uid, family, TCP_EVENT_TYPE_CLOSE);
	bpf_get_current_comm(&event.task, sizeof(event.task));

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
		      &event, sizeof(event));

	return 0;
};

SEC("kprobe/tcp_set_state")
int BPF_KPROBE(enter_tcp_set_state, struct sock *sk, int state)
{
	struct tuple_key_t tuple = {};
	struct event event = {};
	__u16 family;

	if (state != TCP_ESTABLISHED && state != TCP_CLOSE)
		goto end;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);

	if (!fill_tuple(&tuple, sk, family))
		goto end;

	if (state == TCP_CLOSE)
		goto end;

	struct pid_comm_t *p;
	p = bpf_map_lookup_elem(&tuplepid, &tuple);
	if (!p)
		return 0; /* missed entry */

	fill_event(&tuple, &event, p->pid, p->uid, family, TCP_EVENT_TYPE_CONNECT);
	__builtin_memcpy(&event.task, p->comm, sizeof(event.task));

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

end:
	bpf_map_delete_elem(&tuplepid, &tuple);

	return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(exit_inet_csk_accept, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u64 uid_gid = bpf_get_current_uid_gid();
	__u32 uid = uid_gid;
	__u16 sport, family;
	struct event event = {};

	if (!sk)
		return 0;

	if (filter_event(sk, uid, pid))
		return 0;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	sport = BPF_CORE_READ(sk, __sk_common.skc_num);

	struct tuple_key_t t = {};
	fill_tuple(&t, sk, family);
	t.sport = bpf_ntohs(sport);
	/* do not send event if IP address is 0.0.0.0 or port is 0 */
	if (t.saddr_v6 == 0 || t.daddr_v6 == 0 || t.dport == 0 || t.sport == 0)
		return 0;

	fill_event(&t, &event, pid, uid, family, TCP_EVENT_TYPE_ACCEPT);

	bpf_get_current_comm(&event.task, sizeof(event.task));
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

	return 0;
}


char LICENSE[] SEC("license") = "GPL";

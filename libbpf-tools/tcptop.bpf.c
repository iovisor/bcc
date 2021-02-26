// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tcptop.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Define here, because there are conflicts with include files */
#define AF_INET		2
#define AF_INET6	10

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct ipv4_key_t);
    __type(value, size_t);
} ipv4_send_bytes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct ipv4_key_t);
    __type(value, int);
} ipv4_recv_bytes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct ipv6_key_t);
    __type(value, size_t);
} ipv6_send_bytes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct ipv6_key_t);
    __type(value, int);
} ipv6_recv_bytes SEC(".maps");

const volatile pid_t filter_pid = 0;

static __always_inline void
trace_v4(struct pt_regs *ctx, struct ipv4_key_t k4, bool is_send, u16 family)
{
    struct event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return;

	e->pid = k4.pid;
    e->saddr_v4 = k4.saddr;
    e->daddr_v4 = k4.daddr;
    e->sport = k4.lport;
    e->dport = k4.dport;
    e->family = family;
    e->is_send = is_send;

    if(is_send){
        size_t *st;
        st = bpf_map_lookup_elem(&ipv4_send_bytes , &k4);
        if(st) {
            e->send_size = *st;
        }
    }
    else{
        int *cp;
        cp = bpf_map_lookup_elem(&ipv4_recv_bytes , &k4);
        if(cp) {
            e->recv_size = *cp;
        }
    }

    bpf_get_current_comm(e->comm, sizeof(e->comm));
    
    bpf_ringbuf_submit(e, 0);
}

static __always_inline void
trace_v6(struct pt_regs *ctx, struct ipv6_key_t k6, bool is_send, u16 family)
{
    struct event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return;

	e->pid = k6.pid;
    e->saddr_v6 = k6.saddr;
    e->daddr_v6 = k6.daddr;
    e->sport = k6.lport;
    e->dport = k6.dport;
    e->family = family;
    e->is_send = is_send;

    if(is_send){
        size_t *st;
        st = bpf_map_lookup_elem(&ipv6_send_bytes , &k6);
        if(st) {
            e->send_size = *st;
        }
    }
    else{
        int *cp;
        cp = bpf_map_lookup_elem(&ipv6_recv_bytes , &k6);
        if(cp) {
            e->recv_size = *cp;
        }
    }

    bpf_get_current_comm(e->comm, sizeof(e->comm));
    
    bpf_ringbuf_submit(e, 0);
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (filter_pid && pid != filter_pid) {
		return 0;
	}

    u16 family;
	BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);

    if (family == AF_INET) {
        struct ipv4_key_t ipv4_key = {.pid = pid};
		BPF_CORE_READ_INTO(&ipv4_key.saddr, sk, __sk_common.skc_rcv_saddr);
		BPF_CORE_READ_INTO(&ipv4_key.daddr, sk, __sk_common.skc_daddr);
		BPF_CORE_READ_INTO(&ipv4_key.lport, sk, __sk_common.skc_num);
        BPF_CORE_READ_INTO(&ipv4_key.dport, sk, __sk_common.skc_dport);
    	bpf_map_update_elem(&ipv4_send_bytes, &ipv4_key, &size, 0 /* flags: BPF_ANY */);
        trace_v4(ctx, ipv4_key, true, family);

    } else if (family == AF_INET6) {
        struct ipv6_key_t ipv6_key = {.pid = pid};
        BPF_CORE_READ_INTO(&ipv6_key.saddr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        BPF_CORE_READ_INTO(&ipv6_key.daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
        BPF_CORE_READ_INTO(&ipv6_key.lport, sk, __sk_common.skc_num);
        BPF_CORE_READ_INTO(&ipv6_key.dport, sk, __sk_common.skc_dport);
        bpf_map_update_elem(&ipv6_send_bytes, &ipv6_key, &size, 0 /* flags: BPF_ANY */);
        trace_v6(ctx, ipv6_key, true, family);
    }

	return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(tcp_cleanup_rbuf, struct sock *sk, int copied)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (filter_pid && pid != filter_pid) {
		return 0;
	}

    u16 family;
	BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);

    if (copied <= 0)
        return 0;

    if (family == AF_INET) {
        struct ipv4_key_t ipv4_key = {.pid = pid};
		BPF_CORE_READ_INTO(&ipv4_key.saddr, sk, __sk_common.skc_rcv_saddr);
		BPF_CORE_READ_INTO(&ipv4_key.daddr, sk, __sk_common.skc_daddr);
		BPF_CORE_READ_INTO(&ipv4_key.lport, sk, __sk_common.skc_num);
        BPF_CORE_READ_INTO(&ipv4_key.dport, sk, __sk_common.skc_dport);
    	bpf_map_update_elem(&ipv4_recv_bytes, &ipv4_key, &copied, 0 /* flags: BPF_ANY */);
        trace_v4(ctx, ipv4_key, false, family);

    } else if (family == AF_INET6) {
        struct ipv6_key_t ipv6_key = {.pid = pid};
        BPF_CORE_READ_INTO(&ipv6_key.saddr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        BPF_CORE_READ_INTO(&ipv6_key.daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
        BPF_CORE_READ_INTO(&ipv6_key.lport, sk, __sk_common.skc_num);
        BPF_CORE_READ_INTO(&ipv6_key.dport, sk, __sk_common.skc_dport);
        bpf_map_update_elem(&ipv6_recv_bytes, &ipv6_key, &copied, 0 /* flags: BPF_ANY */);
        trace_v6(ctx, ipv6_key, false, family);
    }

	return 0;
}

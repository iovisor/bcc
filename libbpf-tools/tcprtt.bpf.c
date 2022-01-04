// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "tcprtt.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

const volatile bool targ_laddr_hist = false;
const volatile bool targ_raddr_hist = false;
const volatile bool targ_show_ext = false;
const volatile __u16 targ_sport = 0;
const volatile __u16 targ_dport = 0;
const volatile __u32 targ_saddr = 0;
const volatile __u32 targ_daddr = 0;
const volatile bool targ_ms = false;

#define MAX_ENTRIES	10240

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct hist);
} hists SEC(".maps");

static struct hist zero;

SEC("fentry/tcp_rcv_established")
int BPF_PROG(tcp_rcv, struct sock *sk)
{
	const struct inet_sock *inet = (struct inet_sock *)(sk);
	struct tcp_sock *ts;
	struct hist *histp;
	u64 key, slot;
	u32 srtt;

	if (targ_sport && targ_sport != inet->inet_sport)
		return 0;
	if (targ_dport && targ_dport != sk->__sk_common.skc_dport)
		return 0;
	if (targ_saddr && targ_saddr != inet->inet_saddr)
		return 0;
	if (targ_daddr && targ_daddr != sk->__sk_common.skc_daddr)
		return 0;

	if (targ_laddr_hist)
		key = inet->inet_saddr;
	else if (targ_raddr_hist)
		key = inet->sk.__sk_common.skc_daddr;
	else
		key = 0;
	histp = bpf_map_lookup_or_try_init(&hists, &key, &zero);
	if (!histp)
		return 0;
	ts = (struct tcp_sock *)(sk);
	srtt = BPF_CORE_READ(ts, srtt_us) >> 3;
	if (targ_ms)
		srtt /= 1000U;
	slot = log2l(srtt);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->slots[slot], 1);
	if (targ_show_ext) {
		__sync_fetch_and_add(&histp->latency, srtt);
		__sync_fetch_and_add(&histp->cnt, 1);
	}
	return 0;
}

SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(tcp_rcv_kprobe, struct sock *sk)
{
	const struct inet_sock *inet = (struct inet_sock *)(sk);
	u32 srtt, saddr, daddr;
	struct tcp_sock *ts;
	struct hist *histp;
	u64 key, slot;

	if (targ_sport) {
		u16 sport;
		bpf_probe_read_kernel(&sport, sizeof(sport), &inet->inet_sport);
		if (targ_sport != sport)
			return 0;
	}
	if (targ_dport) {
		u16 dport;
		bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
		if (targ_dport != dport)
			return 0;
	}
	bpf_probe_read_kernel(&saddr, sizeof(saddr), &inet->inet_saddr);
	if (targ_saddr && targ_saddr != saddr)
		return 0;
	bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
	if (targ_daddr && targ_daddr != daddr)
		return 0;

	if (targ_laddr_hist)
		key = saddr;
	else if (targ_raddr_hist)
		key = daddr;
	else
		key = 0;
	histp = bpf_map_lookup_or_try_init(&hists, &key, &zero);
	if (!histp)
		return 0;
	ts = (struct tcp_sock *)(sk);
	bpf_probe_read_kernel(&srtt, sizeof(srtt), &ts->srtt_us);
	srtt >>= 3;
	if (targ_ms)
		srtt /= 1000U;
	slot = log2l(srtt);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->slots[slot], 1);
	if (targ_show_ext) {
		__sync_fetch_and_add(&histp->latency, srtt);
		__sync_fetch_and_add(&histp->cnt, 1);
	}
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

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

/* Taken from kernel include/linux/socket.h. */
#define AF_INET		2	/* IP version 4 */
#define AF_INET6	10	/* IP version 6 */


const volatile bool targ_laddr_hist = false;
const volatile bool targ_raddr_hist = false;
const volatile bool targ_show_ext = false;
const volatile __u16 targ_sport = 0;
const volatile __u16 targ_dport = 0;
const volatile __u32 targ_saddr = 0;
const volatile __u32 targ_daddr = 0;
const volatile __u8 targ_saddr_v6[IPV6_LEN] = {};
const volatile __u8 targ_daddr_v6[IPV6_LEN] = {};
const volatile bool targ_ms = false;

#define MAX_ENTRIES	10240

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct hist_key);
	__type(value, struct hist);
} hists SEC(".maps");

static struct hist zero;

/*
 * We cannot use the following:
 * __builtin_memcmp(targ_*addr_v6, *, sizeof(targ_*addr_v6));
 * Indeed, by using the builtin, we would discard the volatile qualifier of
 * targ_*addr_v6, so the compiler would optimize it and replaces the call
 * with 0.
 * So, using the volatile qualifier ensures this function is called at runtime.
 */
static bool inline ipv6_is_not_zero(const volatile __u8 addr[IPV6_LEN])
{
	for (int i = 0; i < IPV6_LEN; i++)
		if (addr[i])
			return true;
	return false;
}

static bool inline ipv6_are_different(const volatile __u8 a[IPV6_LEN], const __u8 b[IPV6_LEN])
{
	for (int i = 0; i < IPV6_LEN; i++)
		if (a[i] != b[i])
			return true;
	return false;
}

static int handle_tcp_rcv_established(struct sock *sk)
{
	const struct inet_sock *inet = (struct inet_sock *)(sk);
	struct tcp_sock *ts;
	struct hist *histp;
	struct hist_key key = {};
	u64 slot;
	u32 srtt;

	if (targ_sport && targ_sport != BPF_CORE_READ(inet, inet_sport))
		return 0;
	if (targ_dport && targ_dport != BPF_CORE_READ(sk, __sk_common.skc_dport))
		return 0;

	key.family = BPF_CORE_READ(sk, __sk_common.skc_family);
	switch (key.family) {
	case AF_INET:
		/* If we set any of IPv6 address, we do not care about IPv4 ones. */
		if (ipv6_is_not_zero(targ_saddr_v6) || ipv6_is_not_zero(targ_daddr_v6))
			return 0;

		if (targ_saddr && targ_saddr != BPF_CORE_READ(inet, inet_saddr))
			return 0;

		if (targ_daddr && targ_daddr != BPF_CORE_READ(sk, __sk_common.skc_daddr))
			return 0;

		break;
	case AF_INET6:
		/*
		 * Reciprocal of the above: if we set any of IPv4 address, we do not care
		 * about IPv6 ones.
		 */
		if (targ_saddr || targ_daddr)
			return 0;

		if (ipv6_is_not_zero(targ_saddr_v6)
			&& ipv6_are_different(targ_saddr_v6, BPF_CORE_READ(inet, pinet6, saddr.in6_u.u6_addr8)))
			return 0;

		if (ipv6_is_not_zero(targ_daddr_v6)
			&& ipv6_are_different(targ_daddr_v6, BPF_CORE_READ(sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8)))
			return 0;

		break;
	default:
		return 0;
	}

	if (targ_laddr_hist) {
		if (key.family == AF_INET6)
			bpf_probe_read_kernel(key.addr, sizeof(key.addr), BPF_CORE_READ(inet, pinet6, saddr.in6_u.u6_addr8));
		else
			bpf_probe_read_kernel(key.addr, sizeof(inet->inet_saddr), &inet->inet_saddr);
	} else if (targ_raddr_hist) {
		if (key.family == AF_INET6)
			bpf_probe_read_kernel(&key.addr, sizeof(key.addr), BPF_CORE_READ(sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8));
		else
			bpf_probe_read_kernel(&key.addr, sizeof(inet->sk.__sk_common.skc_daddr), &inet->sk.__sk_common.skc_daddr);
	} else {
		key.family = 0;
	}

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

SEC("fentry/tcp_rcv_established")
int BPF_PROG(tcp_rcv, struct sock *sk)
{
	return handle_tcp_rcv_established(sk);
}

SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(tcp_rcv_kprobe, struct sock *sk)
{
	return handle_tcp_rcv_established(sk);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

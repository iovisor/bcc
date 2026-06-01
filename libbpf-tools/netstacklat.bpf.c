/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "netstacklat.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

// Mimic macros from /include/net/tcp.h
#define tcp_sk(ptr) container_of(ptr, struct tcp_sock, inet_conn.icsk_inet.sk)
#define TCP_SKB_CB(__skb)	((struct tcp_skb_cb *)&((__skb)->cb[0]))

char LICENSE[] SEC("license") = "GPL";


volatile const __s64 TAI_OFFSET = (37LL * NS_PER_S);
volatile const struct netstacklat_bpf_config user_config = {
	.network_ns = 0,
	.filter_min_sockqueue_len = 0, /* zero means filter is inactive */
	.filter_pid = false,
	.filter_ifindex = false,
	.filter_cgroup = false,
	.groupby_ifindex = false,
	.groupby_cgroup = false,
	.include_hol_blocked = false,
};

/*
 * Alternative definition of sk_buff to handle renaming of the field
 * mono_delivery_time to tstamp_type. See
 * https://nakryiko.com/posts/bpf-core-reference-guide/#handling-incompatible-field-and-type-changes
 */
struct sk_buff___old {
	union {
		ktime_t tstamp;
		u64 skb_mstamp_ns;
	};
	__u8 mono_delivery_time : 1;
} __attribute__((preserve_access_index));

struct tcp_sock_ooo_range {
	u32 prev_n_ooopkts;
	u32 ooo_seq_end;
	/* indicates if ooo_seq_end is still valid (as 0 can be valid seq) */
	bool active;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, HIST_NBUCKETS * NETSTACKLAT_N_HOOKS * 64);
	__type(key, struct hist_key);
	__type(value, u64);
} netstack_latency_seconds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, PID_MAX_LIMIT + 1);
	__type(key, u32);
	__type(value, u64);
} netstack_pidfilter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, IFINDEX_MAX + 1);
	__type(key, u32);
	__type(value, u64);
} netstack_ifindexfilter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PARSED_CGROUPS);
	__type(key, u64);
	__type(value, u64);
} netstack_cgroupfilter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct tcp_sock_ooo_range);
} netstack_tcp_ooo_range SEC(".maps");

/*
 * Is a < b considering u32 wrap around?
 * Based on the before() function in /include/net/tcp.h
 */
static bool u32_lt(u32 a, u32 b)
{
	return (s32)(a - b) < 0;
}

static u32 get_exp2_histogram_bucket_idx(u64 value, u32 max_bucket)
{
	u32 bucket = log2l(value);

	// Right-inclusive histogram, so "round up" the log value
	if (bucket > 0 && 1ULL << bucket < value)
		bucket++;

	if (bucket > max_bucket)
		bucket = max_bucket;

	return bucket;
}

/*
 * Same call signature as the increment_exp2_histogram_nosync macro from
 * https://github.com/cloudflare/ebpf_exporter/blob/master/examples/maps.bpf.h
 * but provided as a function.
 *
 * Unlike the macro, only works with keys of type struct hist_key. The hist_key
 * struct must be provided by value (rather than as a pointer) to keep the same
 * call signature as the ebpf-exporter macro, although this will get inefficent
 * if struct hist_key grows large.
 */
static void increment_exp2_histogram_nosync(void *map, struct hist_key key,
					    u64 value, u32 max_bucket)
{
	u64 *bucket_count;
	u64 zero = 0;

	// Increment histogram
	key.bucket = get_exp2_histogram_bucket_idx(value, max_bucket);
	bucket_count = bpf_map_lookup_or_try_init(map, &key, &zero);
	if (bucket_count)
		(*bucket_count)++;

	// Increment sum at end of histogram
	if (value == 0)
		return;

	key.bucket = max_bucket + 1;
	bucket_count = bpf_map_lookup_or_try_init(map, &key, &zero);
	if (bucket_count)
		*bucket_count += value;
}

static ktime_t time_since(ktime_t tstamp)
{
	ktime_t now;

	if (tstamp <= 0)
		return -1;

	now = bpf_ktime_get_tai_ns() - TAI_OFFSET;
	if (tstamp > now)
		return -1;

	return now - tstamp;
}

static void record_latency(ktime_t latency, const struct hist_key *key)
{
	increment_exp2_histogram_nosync(&netstack_latency_seconds, *key,
					latency, HIST_MAX_LATENCY_SLOT);
}

static void record_latency_since(ktime_t tstamp, const struct hist_key *key)
{
	ktime_t latency = time_since(tstamp);
	if (latency >= 0)
		record_latency(latency, key);
}

static bool filter_ifindex(u32 ifindex)
{
	u64 *ifindex_ok;

	if (!user_config.filter_ifindex)
		// No ifindex filter - all ok
		return true;

	ifindex_ok = bpf_map_lookup_elem(&netstack_ifindexfilter, &ifindex);
	if (!ifindex_ok)
		return false;

	return *ifindex_ok > 0;
}

static __u64 get_network_ns(struct sk_buff *skb, struct sock *sk)
{
	/*
	 * Favor reading from sk due to less redirection (fewer probe reads)
	 * and skb->dev is not always set.
	 */
	if (sk)
		return BPF_CORE_READ(sk->__sk_common.skc_net.net, ns.inum);
	else if (skb)
		return BPF_CORE_READ(skb->dev, nd_net.net, ns.inum);
	return 0;
}

static bool filter_network_ns(struct sk_buff *skb, struct sock *sk)
{
	if (user_config.network_ns == 0)
		return true;

	return get_network_ns(skb, sk) == user_config.network_ns;
}

static bool filter_network(struct sk_buff *skb, struct sock *sk)
{
	if (!filter_ifindex(skb ? skb->skb_iif :
			    sk	? sk->sk_rx_dst_ifindex :
				  0))
		return false;

	return filter_network_ns(skb, sk);
}

static void record_skb_latency(struct sk_buff *skb, struct sock *sk,
			       enum netstacklat_hook hook)
{
	struct hist_key key = { .hook = hook };

	if (bpf_core_field_exists(skb->tstamp_type)) {
		/*
		 * For kernels >= v6.11 the tstamp_type being non-zero
		 * (SKB_CLOCK_REALTIME) implies that skb->tstamp holds a
		 * preserved TX timestamp rather than a RX timestamp. See
		 * https://lore.kernel.org/all/20240509211834.3235191-2-quic_abchauha@quicinc.com/
		 */
		if (BPF_CORE_READ_BITFIELD(skb, tstamp_type) > 0)
			return;

	} else {
		/*
		 * For kernels < v6.11, the field was called mono_delivery_time
		 * instead, see https://lore.kernel.org/all/20220302195525.3480280-1-kafai@fb.com/
		 * Kernels < v5.18 do not have the mono_delivery_field either,
		 * but we do not support those anyways (as they lack the
		 * bpf_ktime_get_tai_ns helper)
		 */
		struct sk_buff___old *skb_old = (void *)skb;
		if (BPF_CORE_READ_BITFIELD(skb_old, mono_delivery_time) > 0)
			return;
	}

	if (!filter_network(skb, sk))
		return;

	if (user_config.groupby_ifindex)
		key.ifindex = skb->skb_iif;

	record_latency_since(skb->tstamp, &key);
}

static bool filter_pid(u32 pid)
{
	u64 *pid_ok;

	if (!user_config.filter_pid)
		// No PID filter - all PIDs ok
		return true;

	pid_ok = bpf_map_lookup_elem(&netstack_pidfilter, &pid);
	if (!pid_ok)
		return false;

	return *pid_ok > 0;
}

static bool filter_cgroup(u64 cgroup_id)
{
	if (!user_config.filter_cgroup)
		// No cgroup filter - all cgroups ok
		return true;

	return bpf_map_lookup_elem(&netstack_cgroupfilter, &cgroup_id) != NULL;
}

static bool filter_current_task(u64 cgroup)
{
	bool ok = true;
	__u32 tgid;

	if (user_config.filter_pid) {
		tgid = bpf_get_current_pid_tgid() >> 32;
		ok = ok && filter_pid(tgid);
	}

	if (user_config.filter_cgroup)
		ok = ok && filter_cgroup(cgroup);

	return ok;
}

static __u32 sk_queue_len(const struct sk_buff_head *list)
{
	return READ_ONCE(list->qlen);
}

static bool sk_backlog_empty(const struct sock *sk)
{
	return READ_ONCE(sk->sk_backlog.tail) == NULL;
}

static bool filter_min_sockqueue_len(struct sock *sk)
{
	const u32 min_qlen = user_config.filter_min_sockqueue_len;

	if (min_qlen == 0)
		return true;

	if (sk_queue_len(&sk->sk_receive_queue) >= min_qlen)
		return true;

	/* Packets can also be on the sk_backlog, but we don't know the number
	 * of SKBs on the queue, because sk_backlog.len is in bytes (based on
	 * skb->truesize).  Thus, if any backlog exists we don't filter.
	 */
	if (!sk_backlog_empty(sk))
		return true;

	return false;
}

/* Get the current receive window end sequence for tp
 * In the kernel receive window checks are done against
 * tp->rcv_nxt + tcp_receive_window(tp). This function should give a comparable
 * result, i.e. rcv_wup + rcv_wnd or rcv_nxt, whichever is higher
 */
static int get_current_rcv_wnd_end(struct tcp_sock *tp, u32 rcv_nxt, u32 *seq)
{
	u32 rcv_wup, rcv_wnd, window;
	int err;

	err = bpf_core_read(&rcv_wup, sizeof(rcv_wup), &tp->rcv_wup);
	if (err) {
		bpf_printk("failed to read tcp_sock->rcv_wup, err=%d", err);
		return err;
	}

	err = bpf_core_read(&rcv_wnd, sizeof(rcv_wnd), &tp->rcv_wnd);
	if (err) {
		bpf_printk("failed to read tcp_sock->rcv_wnd, err=%d", err);
		return err;
	}

	window = rcv_wup + rcv_wnd;
	if (u32_lt(window, rcv_nxt))
		window = rcv_nxt;

	*seq = window;
	return 0;
}

static int current_max_possible_ooo_seq(struct tcp_sock *tp, u32 *seq)
{
	u32 rcv_nxt, cur_rcv_window;
	struct tcp_skb_cb cb;
	int err = 0;

	err = bpf_core_read(&rcv_nxt, sizeof(rcv_nxt), &tp->rcv_nxt);
	if (err) {
		bpf_printk("failed reading tcp_sock->rcv_nxt, err=%d", err);
		return err;
	}

	if (BPF_CORE_READ(tp, out_of_order_queue.rb_node) == NULL) {
		/* No ooo-segments currently in ooo-queue
		 * Any ooo-segments must already have been merged to the
		 * receive queue. Current rcv_nxt must therefore be ahead
		 * of all ooo-segments that have arrived until now.
		 */
		*seq = rcv_nxt;
	} else {
		/*
		 * Some ooo-segments currently in ooo-queue
		 * Max out-of-order seq is given by the seq_end of the tail
		 * skb in the ooo-queue.
		 */
		err = BPF_CORE_READ_INTO(&cb, tp, ooo_last_skb, cb);
		if (err) {
			bpf_printk(
				"failed to read tcp_sock->ooo_last_skb->cb, err=%d",
				err);
			return err;
		}

		// Sanity check - ooo_last_skb->cb.end_seq within the receive window?
		err = get_current_rcv_wnd_end(tp, rcv_nxt, &cur_rcv_window);
		if (err)
			return err;

		/* While seq 0 can be a valid seq, consider it more likely to
		 * be the result of reading from an invalid SKB pointer
		 */
		if (cb.end_seq == 0 || u32_lt(cur_rcv_window, cb.end_seq))
			*seq = cur_rcv_window;
		else
			*seq = cb.end_seq;
	}

	return 0;
}

static bool tcp_read_in_ooo_range(struct tcp_sock *tp,
				  struct tcp_sock_ooo_range *ooo_range)
{
	u32 read_seq;
	int err;

	if (!ooo_range->active)
		return false;

	err = bpf_core_read(&read_seq, sizeof(read_seq), &tp->copied_seq);
	if (err) {
		bpf_printk("failed to read tcp_sock->copied_seq, err=%d", err);
		return true; // Assume we may be in ooo-range
	}

	if (u32_lt(ooo_range->ooo_seq_end, read_seq)) {
		ooo_range->active = false;
		return false;
	} else {
		return true;
	}
}

static bool tcp_read_maybe_holblocked(struct sock *sk)
{
	struct tcp_sock_ooo_range *ooo_range;
	struct tcp_sock *tp = tcp_sk(sk);
	u32 n_ooopkts, nxt_seq;
	int err;

	err = bpf_core_read(&n_ooopkts, sizeof(n_ooopkts), &tp->rcv_ooopack);
	if (err) {
		bpf_printk("failed to read tcp_sock->rcv_ooopack, err=%d\n",
			   err);
		return true; // Assume we may be in ooo-range
	}

	if (n_ooopkts == 0)
		return false;

	ooo_range = bpf_sk_storage_get(&netstack_tcp_ooo_range, sk, NULL,
				       BPF_SK_STORAGE_GET_F_CREATE);
	if (!ooo_range) {
		bpf_printk(
			"failed getting ooo-range socket storage for tcp socket");
		return true; // Assume we may be in ooo-range
	}

	// Increase in ooo-packets since last - figure out next safe seq
	if (n_ooopkts > ooo_range->prev_n_ooopkts) {
		ooo_range->prev_n_ooopkts = n_ooopkts;
		err = current_max_possible_ooo_seq(tp, &nxt_seq);
		if (!err) {
			ooo_range->ooo_seq_end = nxt_seq;
			ooo_range->active = true;
		}
		return true;
	}

	return tcp_read_in_ooo_range(tp, ooo_range);
}

static void record_socket_latency(struct sock *sk, struct sk_buff *skb,
				  ktime_t tstamp, enum netstacklat_hook hook)
{
	struct hist_key key = { .hook = hook };
	u64 cgroup = 0;

	if (!filter_min_sockqueue_len(sk))
		return;

	if (user_config.filter_cgroup || user_config.groupby_cgroup)
		cgroup = bpf_get_current_cgroup_id();

	if (!filter_current_task(cgroup))
		return;

	if (!filter_network(skb, sk))
		return;

	if (user_config.groupby_ifindex)
		key.ifindex = skb ? skb->skb_iif : sk->sk_rx_dst_ifindex;
	if (user_config.groupby_cgroup)
		key.cgroup = cgroup;

	record_latency_since(tstamp, &key);
}

SEC("fentry/ip_rcv_core")
int BPF_PROG(netstacklat_ip_rcv_core, struct sk_buff *skb, void *block,
	     void *tp, void *res, bool compat_mode)
{
	record_skb_latency(skb, NULL, NETSTACKLAT_HOOK_IP_RCV);
	return 0;
}

SEC("fentry/ip6_rcv_core")
int BPF_PROG(netstacklat_ip6_rcv_core, struct sk_buff *skb, void *block,
	     void *tp, void *res, bool compat_mode)
{
	record_skb_latency(skb, NULL, NETSTACKLAT_HOOK_IP_RCV);
	return 0;
}

SEC("fentry/tcp_v4_rcv")
int BPF_PROG(netstacklat_tcp_v4_rcv, struct sk_buff *skb)
{
	record_skb_latency(skb, NULL, NETSTACKLAT_HOOK_TCP_START);
	return 0;
}

SEC("fentry/tcp_v6_rcv")
int BPF_PROG(netstacklat_tcp_v6_rcv, struct sk_buff *skb)
{
	record_skb_latency(skb, NULL, NETSTACKLAT_HOOK_TCP_START);
	return 0;
}

SEC("fentry/udp_rcv")
int BPF_PROG(netstacklat_udp_rcv, struct sk_buff *skb)
{
	record_skb_latency(skb, NULL, NETSTACKLAT_HOOK_UDP_START);
	return 0;
}

SEC("fentry/udpv6_rcv")
int BPF_PROG(netstacklat_udpv6_rcv, struct sk_buff *skb)
{
	record_skb_latency(skb, NULL, NETSTACKLAT_HOOK_UDP_START);
	return 0;
}

SEC("fexit/tcp_queue_rcv")
int BPF_PROG(netstacklat_tcp_queue_rcv, struct sock *sk, struct sk_buff *skb)
{
	record_skb_latency(skb, sk, NETSTACKLAT_HOOK_TCP_SOCK_ENQUEUED);
	return 0;
}

SEC("fexit/__udp_enqueue_schedule_skb")
int BPF_PROG(netstacklat_udp_enqueue_schedule_skb, struct sock *sk,
	     struct sk_buff *skb, int retval)
{
	if (retval == 0)
		record_skb_latency(skb, sk, NETSTACKLAT_HOOK_UDP_SOCK_ENQUEUED);
	return 0;
}

SEC("fentry/tcp_recv_timestamp")
int BPF_PROG(netstacklat_tcp_recv_timestamp, void *msg, struct sock *sk,
	     struct scm_timestamping_internal *tss)
{
	struct timespec64 *ts = &tss->ts[0];

	if (!user_config.include_hol_blocked && tcp_read_maybe_holblocked(sk))
		return 0;

	record_socket_latency(sk, NULL,
			      (ktime_t)ts->tv_sec * NS_PER_S + ts->tv_nsec,
			      NETSTACKLAT_HOOK_TCP_SOCK_READ);
	return 0;
}

SEC("fentry/skb_consume_udp")
int BPF_PROG(netstacklat_skb_consume_udp, struct sock *sk, struct sk_buff *skb,
	     int len)
{
	record_socket_latency(sk, skb, skb->tstamp,
			      NETSTACKLAT_HOOK_UDP_SOCK_READ);
	return 0;
}

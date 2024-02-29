// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Wenbo Zhang */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "futexctn.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

#define MAX_ENTRIES	10240

#define FUTEX_WAIT		0
#define FUTEX_PRIVATE_FLAG	128
#define FUTEX_CLOCK_REALTIME	256
#define FUTEX_CMD_MASK		~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME)

const volatile bool targ_summary = false;
const volatile bool targ_ms = false;
const volatile __u64 targ_lock = 0;
const volatile pid_t targ_pid = 0;
const volatile pid_t targ_tid = 0;

struct val_t {
	u64 ts;
	u64 uaddr;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct val_t);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
} stackmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct hist_key);
	__type(value, struct hist);
} hists SEC(".maps");

static struct hist initial_hist = {};

SEC("tracepoint/syscalls/sys_enter_futex")
int futex_enter(struct syscall_trace_enter *ctx)
{
	struct val_t v = {};
	u64 pid_tgid;
	u32 tid;

	if (((int)ctx->args[1] & FUTEX_CMD_MASK) != FUTEX_WAIT)
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	tid = (__u32)pid_tgid;
	if (targ_pid && targ_pid != pid_tgid >> 32)
		return 0;
	if (targ_tid && targ_tid != tid)
		return 0;
	v.uaddr = ctx->args[0];
	if (targ_lock && targ_lock != v.uaddr)
		return 0;
	v.ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start, &pid_tgid, &v, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_futex")
int futex_exit(struct syscall_trace_exit *ctx)
{
	u64 pid_tgid, slot, ts, min, max;
	struct hist_key hkey = {};
	struct hist *histp;
	struct val_t *vp;
	s64 delta;

	ts = bpf_ktime_get_ns();
	pid_tgid = bpf_get_current_pid_tgid();
	vp = bpf_map_lookup_elem(&start, &pid_tgid);
	if (!vp)
		return 0;
	if ((int)ctx->ret < 0)
		goto cleanup;

	delta = (s64)(ts - vp->ts);
	if (delta < 0)
		goto cleanup;

	hkey.pid_tgid = pid_tgid;
	hkey.uaddr = vp->uaddr;
	if (!targ_summary)
		hkey.user_stack_id = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
	else
		hkey.pid_tgid >>= 32;

	histp = bpf_map_lookup_or_try_init(&hists, &hkey, &initial_hist);
	if (!histp)
		goto cleanup;

	if (targ_ms)
		delta /= 1000000U;
	else
		delta /= 1000U;

	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->slots[slot], 1);
	__sync_fetch_and_add(&histp->contended, 1);
	__sync_fetch_and_add(&histp->total_elapsed, delta);
	min = __sync_fetch_and_add(&histp->min, 0);
	if (!min || min > delta)
		__sync_val_compare_and_swap(&histp->min, min, delta);
	max = __sync_fetch_and_add(&histp->max, 0);
	if (max < delta)
		__sync_val_compare_and_swap(&histp->max, max, delta);
	bpf_get_current_comm(&histp->comm, sizeof(histp->comm));

cleanup:
	bpf_map_delete_elem(&start, &pid_tgid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

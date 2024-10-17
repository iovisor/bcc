// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "offcputime.h"
#include "core_fixes.bpf.h"

#define PF_KTHREAD		0x00200000	/* I am a kernel thread */
#define MAX_ENTRIES		10240

const volatile bool kernel_threads_only = false;
const volatile bool user_threads_only = false;
const volatile __u64 max_block_ns = -1;
const volatile __u64 min_block_ns = 1;
const volatile bool filter_by_tgid = false;
const volatile bool filter_by_pid = false;
const volatile long state = -1;

struct internal_key {
	u64 start_ts;
	struct key_t key;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct internal_key);
	__uint(max_entries, MAX_ENTRIES);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
} stackmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct key_t);
	__type(value, struct val_t);
	__uint(max_entries, MAX_ENTRIES);
} info SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u8);
	__uint(max_entries, MAX_PID_NR);
} tgids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u8);
	__uint(max_entries, MAX_TID_NR);
} pids SEC(".maps");

static bool allow_record(struct task_struct *t)
{
	u32 tgid = BPF_CORE_READ(t, tgid);
	u32 pid = BPF_CORE_READ(t, pid);

	if (filter_by_tgid && !bpf_map_lookup_elem(&tgids, &tgid))
		return false;
	if (filter_by_pid && !bpf_map_lookup_elem(&pids, &pid))
		return false;
	if (user_threads_only && (BPF_CORE_READ(t, flags) & PF_KTHREAD))
		return false;
	else if (kernel_threads_only && !(BPF_CORE_READ(t, flags) & PF_KTHREAD))
		return false;
	if (state != -1 && get_task_state(t) != state)
		return false;
	return true;
}

static int handle_sched_switch(void *ctx, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	struct internal_key *i_keyp, i_key;
	struct val_t *valp, val;
	s64 delta;
	u32 pid;

	if (allow_record(prev)) {
		pid = BPF_CORE_READ(prev, pid);
		/* To distinguish idle threads of different cores */
		if (!pid)
			pid = bpf_get_smp_processor_id();
		i_key.key.pid = pid;
		i_key.key.tgid = BPF_CORE_READ(prev, tgid);
		i_key.start_ts = bpf_ktime_get_ns();

		if (BPF_CORE_READ(prev, flags) & PF_KTHREAD)
			i_key.key.user_stack_id = -1;
		else
			i_key.key.user_stack_id = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
		i_key.key.kern_stack_id = bpf_get_stackid(ctx, &stackmap, 0);
		bpf_map_update_elem(&start, &pid, &i_key, 0);
		bpf_probe_read_kernel_str(&val.comm, sizeof(prev->comm), BPF_CORE_READ(prev, comm));
		val.delta = 0;
		bpf_map_update_elem(&info, &i_key.key, &val, BPF_NOEXIST);
	}

	pid = BPF_CORE_READ(next, pid);
	i_keyp = bpf_map_lookup_elem(&start, &pid);
	if (!i_keyp)
		return 0;
	delta = (s64)(bpf_ktime_get_ns() - i_keyp->start_ts);
	if (delta < 0)
		goto cleanup;
	delta /= 1000U;
	if (delta < min_block_ns || delta > max_block_ns)
		goto cleanup;
	valp = bpf_map_lookup_elem(&info, &i_keyp->key);
	if (!valp)
		goto cleanup;
	__sync_fetch_and_add(&valp->delta, delta);

cleanup:
	bpf_map_delete_elem(&start, &pid);
	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	return handle_sched_switch(ctx, preempt, prev, next);
}

SEC("raw_tp/sched_switch")
int BPF_PROG(sched_switch_raw, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	return handle_sched_switch(ctx, preempt, prev, next);
}

char LICENSE[] SEC("license") = "GPL";

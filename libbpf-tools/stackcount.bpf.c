// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025, Realtek

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "stackcount.h"
#include "core_fixes.bpf.h"

#define MAX_ENTRIES 10240

const volatile int target_pid = 0;
const volatile int target_cpu = -1;
const volatile bool kernel_stacks_only = false;
const volatile bool user_stacks_only = false;
const volatile bool per_pid = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct key_t);
	__type(value, u64);
} counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
} stack_traces SEC(".maps");

static int trace_count(void *ctx)
{
	if (target_cpu >= 0 && bpf_get_smp_processor_id() != (u32)target_cpu)
		return 0;

	u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (target_pid != 0 && tgid != target_pid)
		return 0;

	struct key_t key = {};
	s32 kern_stack_id = -1, user_stack_id = -1;

	if (per_pid) {
		key.tgid = tgid;
		bpf_get_current_comm(&key.name, sizeof(key.name));
	}

	if (!user_stacks_only)
		kern_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);

	if (!kernel_stacks_only)
		user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);

	key.kernel_stack_id = kern_stack_id;
	key.user_stack_id = user_stack_id;

	u64 *count;

	count = bpf_map_lookup_elem(&counts, &key);
	if (count) {
		__sync_fetch_and_add(count, 1);
	} else {
		u64 init_val = 1;
		bpf_map_update_elem(&counts, &key, &init_val, BPF_ANY);
	}

	return 0;
}

SEC("kprobe/dummy")
int BPF_KPROBE(kprobe_prog)
{
	return trace_count(ctx);
}

SEC("tracepoint/dummy/dummy")
int BPF_PROG(tp_prog)
{
	return trace_count(ctx);
}

SEC("uprobe/dummy")
int BPF_KPROBE(uprobe_prog)
{
	return trace_count(ctx);
}

char LICENSE[] SEC("license") = "GPL";

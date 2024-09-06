// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 Feng Yang
// Based on funcinterval.py from BCC by Edward Wu

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "funcinterval.h"
#include "maps.bpf.h"
#include "bits.bpf.h"

const volatile pid_t targ_pid = 0;
const volatile bool targ_ms = false;

static struct hist zero = {0};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, u64);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct hist);
} hists SEC(".maps");

static int trace_func_entry(void *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 index = 0, tgid = pid_tgid >> 32;
	u64 *tsp, ts = bpf_ktime_get_ns(), delta, slot;
	struct hist *histp;

	if (targ_pid && tgid != targ_pid)
		return 0;

	tsp = bpf_map_lookup_elem(&start, &index);
	if (tsp == 0)
		goto out;

	histp = bpf_map_lookup_or_try_init(&hists, &index, &zero);
	if (!histp)
		return 0;

	delta = ts - *tsp;
	if (targ_ms)
		delta /= 1000000U;
	else
		delta /= 1000U;

	// store as histogram
	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->slots[slot], 1);

out:
	bpf_map_update_elem(&start, &index, &ts, BPF_ANY);

	return 0;
}

SEC("kprobe")
int BPF_KPROBE(function_entry)
{
	return trace_func_entry(ctx);
}

SEC("tracepoint")
int tracepoint_entry(void *ctx)
{
	return trace_func_entry(ctx);
}

SEC("uprobe")
int BPF_KPROBE(function_uprobe_entry)
{
	return trace_func_entry(ctx);
}

char LICENSE[] SEC("license") = "GPL";
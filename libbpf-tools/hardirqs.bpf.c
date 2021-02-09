// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "hardirqs.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

#define MAX_ENTRIES	256

const volatile bool targ_dist = false;
const volatile bool targ_ns = false;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct irq_key);
	__type(value, struct info);
} infos SEC(".maps");

static struct info zero;

SEC("tracepoint/irq/irq_handler_entry")
int handle__irq_handler(struct trace_event_raw_irq_handler_entry *ctx)
{
	struct irq_key key = {};
	struct info *info;

	bpf_probe_read_kernel_str(&key.name, sizeof(key.name), ctx->__data);
	info = bpf_map_lookup_or_try_init(&infos, &key, &zero);
	if (!info)
		return 0;
	info->count += 1;
	return 0;
}

SEC("tp_btf/irq_handler_entry")
int BPF_PROG(irq_handler_entry)
{
	u64 ts = bpf_ktime_get_ns();
	u32 key = 0;

	bpf_map_update_elem(&start, &key, &ts, 0);
	return 0;
}

SEC("tp_btf/irq_handler_exit")
int BPF_PROG(irq_handler_exit_exit, int irq, struct irqaction *action)
{
	struct irq_key ikey = {};
	struct info *info;
	u32 key = 0;
	s64 delta;
	u64 *tsp;

	tsp = bpf_map_lookup_elem(&start, &key);
	if (!tsp || !*tsp)
		return 0;

	delta = bpf_ktime_get_ns() - *tsp;
	if (delta < 0)
		return 0;
	if (!targ_ns)
		delta /= 1000U;

	bpf_probe_read_kernel_str(&ikey.name, sizeof(ikey.name), action->name);
	info = bpf_map_lookup_or_try_init(&infos, &ikey, &zero);
	if (!info)
		return 0;

	if (!targ_dist) {
		info->count += delta;
	} else {
		u64 slot;

		slot = log2(delta);
		if (slot >= MAX_SLOTS)
			slot = MAX_SLOTS - 1;
		info->slots[slot]++;
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";

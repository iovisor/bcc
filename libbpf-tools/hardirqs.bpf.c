// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "hardirqs.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

#define MAX_ENTRIES	256

const volatile bool filter_cg = false;
const volatile bool targ_dist = false;
const volatile bool targ_ns = false;
const volatile bool cpu = false;
const volatile int targ_cpu = -1;

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

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

static __always_inline bool is_target_cpu() {
	if (targ_cpu < 0)
		return true;

	return targ_cpu == bpf_get_smp_processor_id();
}

static int handle_entry(int irq, struct irqaction *action)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;
	if (!is_target_cpu())
		return 0;

	u64 ts = bpf_ktime_get_ns();
	u32 key = 0;

	bpf_map_update_elem(&start, &key, &ts, BPF_ANY);

	return 0;
}

static int handle_exit(int irq, struct irqaction *action)
{
	struct irq_key ikey = {};
	struct info *info;
	u32 key = 0;
	u64 delta;
	u64 *tsp;

	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	if (!is_target_cpu())
		return 0;

	tsp = bpf_map_lookup_elem(&start, &key);
	if (!tsp)
		return 0;

	delta = bpf_ktime_get_ns() - *tsp;
	if (!targ_ns)
		delta /= 1000U;

	bpf_probe_read_kernel_str(&ikey.name, sizeof(ikey.name), BPF_CORE_READ(action, name));
	if (cpu)
		ikey.cpu = bpf_get_smp_processor_id();
	info = bpf_map_lookup_or_try_init(&infos, &ikey, &zero);
	if (!info)
		return 0;

	info->count += 1;

	if (!targ_dist) {
		info->total_time += delta;
		if (delta > info->max_time)
			info->max_time = delta;
	} else {
		u64 slot;

		slot = log2l(delta);
		if (slot >= MAX_SLOTS)
			slot = MAX_SLOTS - 1;
		info->slots[slot]++;
	}

	return 0;
}

SEC("tp_btf/irq_handler_entry")
int BPF_PROG(irq_handler_entry_btf, int irq, struct irqaction *action)
{
	return handle_entry(irq, action);
}

SEC("tp_btf/irq_handler_exit")
int BPF_PROG(irq_handler_exit_btf, int irq, struct irqaction *action)
{
	return handle_exit(irq, action);
}

SEC("raw_tp/irq_handler_entry")
int BPF_PROG(irq_handler_entry, int irq, struct irqaction *action)
{
	return handle_entry(irq, action);
}

SEC("raw_tp/irq_handler_exit")
int BPF_PROG(irq_handler_exit, int irq, struct irqaction *action)
{
	return handle_exit(irq, action);
}

char LICENSE[] SEC("license") = "GPL";

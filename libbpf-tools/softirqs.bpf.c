// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "softirqs.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

const volatile bool targ_dist = false;
const volatile bool targ_ns = false;
const volatile int targ_cpu = -1;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

__u64 counts[NR_SOFTIRQS] = {};
__u64 time[NR_SOFTIRQS] = {};
struct hist hists[NR_SOFTIRQS] = {};

static bool is_target_cpu() {
	if (targ_cpu < 0)
		return true;

	return bpf_get_smp_processor_id() == targ_cpu;
}

static int handle_entry(unsigned int vec_nr)
{
	if (!is_target_cpu())
		return 0;

	u64 ts = bpf_ktime_get_ns();
	u32 key = 0;

	bpf_map_update_elem(&start, &key, &ts, BPF_ANY);
	return 0;
}

static int handle_exit(unsigned int vec_nr)
{
	if (!is_target_cpu())
		return 0;

	u64 delta, *tsp;
	u32 key = 0;

	if (vec_nr >= NR_SOFTIRQS)
		return 0;
	tsp = bpf_map_lookup_elem(&start, &key);
	if (!tsp)
		return 0;
	delta = bpf_ktime_get_ns() - *tsp;
	if (!targ_ns)
		delta /= 1000U;

	if (!targ_dist) {
		__sync_fetch_and_add(&counts[vec_nr], 1);
		__sync_fetch_and_add(&time[vec_nr], delta);
	} else {
		struct hist *hist;
		u64 slot;

		hist = &hists[vec_nr];
		slot = log2l(delta);
		if (slot >= MAX_SLOTS)
			slot = MAX_SLOTS - 1;
		__sync_fetch_and_add(&hist->slots[slot], 1);
	}

	return 0;
}

SEC("tp_btf/softirq_entry")
int BPF_PROG(softirq_entry_btf, unsigned int vec_nr)
{
	return handle_entry(vec_nr);
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(softirq_exit_btf, unsigned int vec_nr)
{
	return handle_exit(vec_nr);
}

SEC("raw_tp/softirq_entry")
int BPF_PROG(softirq_entry, unsigned int vec_nr)
{
	return handle_entry(vec_nr);
}

SEC("raw_tp/softirq_exit")
int BPF_PROG(softirq_exit, unsigned int vec_nr)
{
	return handle_exit(vec_nr);
}

char LICENSE[] SEC("license") = "GPL";

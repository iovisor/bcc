// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "cpufreq.h"
#include "maps.bpf.h"

__u32 freqs_mhz[MAX_CPU_NR] = {};
static struct hist zero;
struct hist syswide = {};
bool filter_cg = false;

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct hkey);
	__type(value, struct hist);
} hists SEC(".maps");

#define clamp_umax(VAR, UMAX)						\
	asm volatile (							\
		"if %0 <= %[max] goto +1\n"				\
		"%0 = %[max]\n"						\
		: "+r"(VAR)						\
		: [max]"i"(UMAX)					\
	)

SEC("tp_btf/cpu_frequency")
int BPF_PROG(cpu_frequency, unsigned int state, unsigned int cpu_id)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	if (cpu_id >= MAX_CPU_NR)
		return 0;

	clamp_umax(cpu_id, MAX_CPU_NR - 1);
	freqs_mhz[cpu_id] = state / 1000;
	return 0;
}

SEC("perf_event")
int do_sample(struct bpf_perf_event_data *ctx)
{
	u32 freq_mhz, pid = bpf_get_current_pid_tgid();
	u64 slot, cpu = bpf_get_smp_processor_id();
	struct hist *hist;
	struct hkey hkey;

	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	if (cpu >= MAX_CPU_NR)
		return 0;
	clamp_umax(cpu, MAX_CPU_NR - 1);
	freq_mhz = freqs_mhz[cpu];
	if (!freq_mhz)
		return 0;
	/*
	 * The range of the linear histogram is 0 ~ 5000mhz,
	 * and the step size is 200.
	 */
	slot = freq_mhz / HIST_STEP_SIZE;
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&syswide.slots[slot], 1);
	if (!pid)
		return 0;
	bpf_get_current_comm(&hkey.comm, sizeof(hkey.comm));
	hist = bpf_map_lookup_or_try_init(&hists, &hkey, &zero);
	if (!hist)
		return 0;
	__sync_fetch_and_add(&hist->slots[slot], 1);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

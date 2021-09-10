// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "llcstat.h"

#define MAX_ENTRIES	10240

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct info);
} infos SEC(".maps");

static __always_inline
int trace_event(__u64 sample_period, bool miss)
{
	u64 pid = bpf_get_current_pid_tgid();
	u32 cpu = bpf_get_smp_processor_id();
	struct info *infop, info = {};
	u64 key = pid << 32 | cpu;

	infop = bpf_map_lookup_elem(&infos, &key);
	if (!infop) {
		bpf_get_current_comm(info.comm, sizeof(info.comm));
		infop = &info;
	}
	if (miss)
		infop->miss += sample_period;
	else
		infop->ref += sample_period;
	if (infop == &info)
		bpf_map_update_elem(&infos, &key, infop, 0);
	return 0;
}

SEC("perf_event/1")
int on_cache_miss(struct bpf_perf_event_data *ctx)
{
	return trace_event(ctx->sample_period, true);
}

SEC("perf_event/2")
int on_cache_ref(struct bpf_perf_event_data *ctx)
{
	return trace_event(ctx->sample_period, false);
}

char LICENSE[] SEC("license") = "GPL";

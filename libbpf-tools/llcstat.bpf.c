// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "maps.bpf.h"
#include "llcstat.h"

#define MAX_ENTRIES	10240

const volatile bool targ_per_thread = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct llcstat_key_info);
	__type(value, struct llcstat_value_info);
} infos SEC(".maps");

static __always_inline
int trace_event(__u64 sample_period, bool miss)
{
	struct llcstat_key_info key = {};
	struct llcstat_value_info *infop, zero = {};

	u64 pid_tgid = bpf_get_current_pid_tgid();
	key.cpu = bpf_get_smp_processor_id();
	key.pid = pid_tgid >> 32;
	if (targ_per_thread)
		key.tid = (u32)pid_tgid;
	else
		key.tid = key.pid;

	infop = bpf_map_lookup_or_try_init(&infos, &key, &zero);
	if (!infop)
		return 0;
	if (miss)
		infop->miss += sample_period;
	else
		infop->ref += sample_period;
	bpf_get_current_comm(infop->comm, sizeof(infop->comm));

	return 0;
}

SEC("perf_event")
int on_cache_miss(struct bpf_perf_event_data *ctx)
{
	return trace_event(ctx->sample_period, true);
}

SEC("perf_event")
int on_cache_ref(struct bpf_perf_event_data *ctx)
{
	return trace_event(ctx->sample_period, false);
}

char LICENSE[] SEC("license") = "GPL";

// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "biopattern.h"
#include "maps.bpf.h"
#include "core_fixes.bpf.h"

const volatile bool filter_dev = false;
const volatile __u32 targ_dev = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, u32);
	__type(value, struct counter);
} counters SEC(".maps");

SEC("tracepoint/block/block_rq_complete")
int handle__block_rq_complete(void *args)
{
	struct counter *counterp, zero = {};
	sector_t sector;
	u32 nr_sector;
	u32 dev;

	if (has_block_rq_completion()) {
		struct trace_event_raw_block_rq_completion___x *ctx = args;
		sector = BPF_CORE_READ(ctx, sector);
		nr_sector = BPF_CORE_READ(ctx, nr_sector);
		dev = BPF_CORE_READ(ctx, dev);
	} else {
		struct trace_event_raw_block_rq_complete___x *ctx = args;
		sector = BPF_CORE_READ(ctx, sector);
		nr_sector = BPF_CORE_READ(ctx, nr_sector);
		dev = BPF_CORE_READ(ctx, dev);
	}

	if (filter_dev && targ_dev != dev)
		return 0;

	counterp = bpf_map_lookup_or_try_init(&counters, &dev, &zero);
	if (!counterp)
		return 0;
	if (counterp->last_sector) {
		if (counterp->last_sector == sector)
			__sync_fetch_and_add(&counterp->sequential, 1);
		else
			__sync_fetch_and_add(&counterp->random, 1);
		__sync_fetch_and_add(&counterp->bytes, nr_sector * 512);
	}
	counterp->last_sector = sector + nr_sector;
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

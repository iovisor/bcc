// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "biopattern.h"
#include "maps.bpf.h"

const volatile dev_t targ_dev = -1;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, dev_t);
	__type(value, struct counter);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} counters SEC(".maps");

SEC("tracepoint/block/block_rq_complete")
int tp__block__block_rq_complete(struct trace_event_raw_block_rq_complete *ctx)
{
	sector_t *last_sectorp,  sector = ctx->sector;
	struct counter *counterp, zero = {};
	u32 nr_sector = ctx->nr_sector;
	dev_t dev = ctx->dev;

	if (targ_dev != -1 && targ_dev != dev)
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

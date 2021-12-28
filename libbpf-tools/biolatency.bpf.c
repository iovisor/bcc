// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "biolatency.h"
#include "bits.bpf.h"

#define MAX_ENTRIES	10240

extern int LINUX_KERNEL_VERSION __kconfig;

const volatile bool filter_cg = false;
const volatile bool targ_per_disk = false;
const volatile bool targ_per_flag = false;
const volatile bool targ_queued = false;
const volatile bool targ_ms = false;
const volatile bool filter_dev = false;
const volatile __u32 targ_dev = 0;

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct request *);
	__type(value, u64);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} start SEC(".maps");

static struct hist initial_hist;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct hist_key);
	__type(value, struct hist);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} hists SEC(".maps");

static __always_inline
int trace_rq_start(struct request *rq, int issue)
{
	if (issue && targ_queued && BPF_CORE_READ(rq->q, elevator))
		return 0;

	u64 ts = bpf_ktime_get_ns();

	if (filter_dev) {
		struct gendisk *disk = BPF_CORE_READ(rq, rq_disk);
		u32 dev;

		dev = disk ? MKDEV(BPF_CORE_READ(disk, major),
				BPF_CORE_READ(disk, first_minor)) : 0;
		if (targ_dev != dev)
			return 0;
	}
	bpf_map_update_elem(&start, &rq, &ts, 0);
	return 0;
}

SEC("tp_btf/block_rq_insert")
int block_rq_insert(u64 *ctx)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	/**
	 * commit a54895fa (v5.11-rc1) changed tracepoint argument list
	 * from TP_PROTO(struct request_queue *q, struct request *rq)
	 * to TP_PROTO(struct request *rq)
	 */
	if (LINUX_KERNEL_VERSION <= KERNEL_VERSION(5, 10, 0))
		return trace_rq_start((void *)ctx[1], false);
	else
		return trace_rq_start((void *)ctx[0], false);
}

SEC("tp_btf/block_rq_issue")
int block_rq_issue(u64 *ctx)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	/**
	 * commit a54895fa (v5.11-rc1) changed tracepoint argument list
	 * from TP_PROTO(struct request_queue *q, struct request *rq)
	 * to TP_PROTO(struct request *rq)
	 */
	if (LINUX_KERNEL_VERSION <= KERNEL_VERSION(5, 10, 0))
		return trace_rq_start((void *)ctx[1], true);
	else
		return trace_rq_start((void *)ctx[0], true);
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(block_rq_complete, struct request *rq, int error,
	unsigned int nr_bytes)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	u64 slot, *tsp, ts = bpf_ktime_get_ns();
	struct hist_key hkey = {};
	struct hist *histp;
	s64 delta;

	tsp = bpf_map_lookup_elem(&start, &rq);
	if (!tsp)
		return 0;
	delta = (s64)(ts - *tsp);
	if (delta < 0)
		goto cleanup;

	if (targ_per_disk) {
		struct gendisk *disk = BPF_CORE_READ(rq, rq_disk);

		hkey.dev = disk ? MKDEV(BPF_CORE_READ(disk, major),
					BPF_CORE_READ(disk, first_minor)) : 0;
	}
	if (targ_per_flag)
		hkey.cmd_flags = rq->cmd_flags;

	histp = bpf_map_lookup_elem(&hists, &hkey);
	if (!histp) {
		bpf_map_update_elem(&hists, &hkey, &initial_hist, 0);
		histp = bpf_map_lookup_elem(&hists, &hkey);
		if (!histp)
			goto cleanup;
	}

	if (targ_ms)
		delta /= 1000000U;
	else
		delta /= 1000U;
	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->slots[slot], 1);

cleanup:
	bpf_map_delete_elem(&start, &rq);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

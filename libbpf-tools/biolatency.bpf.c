// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "biolatency.h"
#include "bits.bpf.h"

#define MAX_ENTRIES 10240

const volatile char targ_disk[DISK_NAME_LEN] = {};
const volatile bool targ_per_disk = false;
const volatile bool targ_per_flag = false;
const volatile bool targ_queued = false;
const volatile bool targ_ms = false;

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

static __always_inline bool disk_filtered(const char *disk)
{
	int i;

	for (i = 0; targ_disk[i] != '\0' && i < DISK_NAME_LEN; i++) {
		if (disk[i] != targ_disk[i])
			return false;
	}
	return true;
}

static __always_inline
int trace_rq_start(struct request *rq)
{
	u64 ts = bpf_ktime_get_ns();
	char disk[DISK_NAME_LEN];

	bpf_probe_read_kernel_str(&disk, sizeof(disk), rq->rq_disk->disk_name);
	if (!disk_filtered(disk))
		return 0;

	bpf_map_update_elem(&start, &rq, &ts, 0);
	return 0;
}

SEC("tp_btf/block_rq_insert")
int BPF_PROG(tp_btf__block_rq_insert, struct request_queue *q,
	     struct request *rq)
{
	return trace_rq_start(rq);
}

SEC("tp_btf/block_rq_issue")
int BPF_PROG(tp_btf__block_rq_issue, struct request_queue *q,
	     struct request *rq)
{
	if (targ_queued && BPF_CORE_READ(q, elevator))
		return 0;
	return trace_rq_start(rq);
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(tp_btf__block_rq_complete, struct request *rq, int error,
	     unsigned int nr_bytes)
{
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

	if (targ_per_disk)
		bpf_probe_read_kernel_str(&hkey.disk, sizeof(hkey.disk),
					rq->rq_disk->disk_name);
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
		delta /= 1000000;
	else
		delta /= 1000;
	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->slots[slot], 1);

cleanup:
	bpf_map_delete_elem(&start, &rq);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

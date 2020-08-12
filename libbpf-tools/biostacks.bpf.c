// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "biostacks.h"
#include "bits.bpf.h"

#define MAX_ENTRIES 10240

const volatile char targ_disk[DISK_NAME_LEN] = {};
const volatile bool targ_ms = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct request *);
	__type(value, u64);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct rqinfo);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} rqinfos SEC(".maps");

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
int trace_start(struct rqinfo *rqinfo, void *ctx, struct request *rq,
		u32 pid, u64 ts)
{
	rqinfo->pid = pid;
	rqinfo->kern_stack_size = bpf_get_stack(ctx, rqinfo->kern_stack,
					sizeof(rqinfo->kern_stack), 0);
	rqinfo->start_ts = ts;
	bpf_get_current_comm(&rqinfo->comm, sizeof(rqinfo->comm));
	bpf_map_update_elem(&start, &rq, &ts, 0);
	bpf_map_update_elem(&rqinfos, &ts, rqinfo, 0);
	return 0;
}

SEC("fentry/blk_account_io_start")
int BPF_PROG(fentry__blk_account_io_start, struct request *rq)
{
	u32 pid = bpf_get_current_pid_tgid();
	u64 ts = bpf_ktime_get_ns();
	struct rqinfo rqinfo = {};

	bpf_probe_read_kernel_str(&rqinfo.disk, sizeof(rqinfo.disk),
				rq->rq_disk->disk_name);
	if (!disk_filtered(rqinfo.disk))
		return 0;
	return trace_start(&rqinfo, ctx, rq, pid, ts);
}

SEC("kprobe/blk_account_io_merge_bio")
int BPF_KPROBE(kprobe__blk_account_io_merge_bio, struct request *rq)
{
	u32 pid = bpf_get_current_pid_tgid();
	u64 *tsp, ts = bpf_ktime_get_ns();
	struct rqinfo rqinfo = {};

	BPF_CORE_READ_STR_INTO(&rqinfo, rq, rq_disk, disk_name);
	tsp = bpf_map_lookup_elem(&start, &rq);
	if (tsp) {
		bpf_map_delete_elem(&rqinfos, tsp);
	} else {
		if (!disk_filtered(rqinfo.disk))
			return 0;
	}
	return trace_start(&rqinfo, ctx, rq, pid, ts);
}

SEC("fentry/blk_account_io_done")
int BPF_PROG(fentry__blk_account_io_done, struct request *rq)
{
	u64 slot, *tsp, ts = bpf_ktime_get_ns();
	struct rqinfo *rqinfop;
	s64 delta;

	tsp = bpf_map_lookup_elem(&start, &rq);
	if (!tsp)
		return 0;
	rqinfop = bpf_map_lookup_elem(&rqinfos, tsp);
	if (!rqinfop)
		goto cleanup;
	delta = (s64)(ts - rqinfop->start_ts);
	if (delta < 0) {
		bpf_map_delete_elem(&rqinfos, tsp);
		goto cleanup;
	}
	if (targ_ms)
		delta /= 1000000;
	else
		delta /= 1000;
	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&rqinfop->slots[slot], 1);

cleanup:
	bpf_map_delete_elem(&start, &rq);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

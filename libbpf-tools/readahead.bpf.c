// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "readahead.h"
#include "bits.bpf.h"

#define MAX_ENTRIES	10240

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, u64);
} in_readahead SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct folio *);
	__type(value, u64);
} birth SEC(".maps");

struct hist hist = {};

SEC("fentry/page_cache_ra_unbounded")
int BPF_PROG(page_cache_ra_unbounded)
{
	u32 pid = bpf_get_current_pid_tgid();
	u64 one = 1;

	bpf_map_update_elem(&in_readahead, &pid, &one, 0);
	return 0;
}

SEC("fexit/filemap_alloc_folio")
int BPF_PROG(filemap_alloc_folio_ret, gfp_t gfp, struct folio *ret)
{
	u32 pid = bpf_get_current_pid_tgid();
	u64 ts;

	if (!bpf_map_lookup_elem(&in_readahead, &pid))
		return 0;

	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&birth, &ret, &ts, 0);
	__sync_fetch_and_add(&hist.unused, 1);
	__sync_fetch_and_add(&hist.total, 1);

	return 0;
}

SEC("fexit/page_cache_ra_unbounded")
int BPF_PROG(page_cache_ra_unbounded_ret)
{
	u32 pid = bpf_get_current_pid_tgid();

	bpf_map_delete_elem(&in_readahead, &pid);
	return 0;
}

SEC("fentry/folio_mark_accessed")
int BPF_PROG(folio_mark_accessed, struct folio *folio)
{
	u64 *tsp, slot, ts = bpf_ktime_get_ns();
	s64 delta;

	tsp = bpf_map_lookup_elem(&birth, &folio);
	if (!tsp)
		return 0;
	delta = (s64)(ts - *tsp);
	if (delta < 0)
		goto update_and_cleanup;
	slot = log2l(delta / 1000000U);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&hist.slots[slot], 1);

update_and_cleanup:
	__sync_fetch_and_add(&hist.unused, -1);
	bpf_map_delete_elem(&birth, &folio);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";

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
	__type(key, struct page *);
	__type(value, u64);
} birth SEC(".maps");

struct hist hist = {};

static int do_page_cache_alloc_ret(struct page *ret)
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

static int do_mark_page_accessed(struct page *page)
{
	u64 *tsp, slot, ts = bpf_ktime_get_ns();
	s64 delta;

	tsp = bpf_map_lookup_elem(&birth, &page);
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
	bpf_map_delete_elem(&birth, &page);

	return 0;
}

static int do_page_cache_ra(void)
{
	u32 pid = bpf_get_current_pid_tgid();
	u64 one = 1;

	bpf_map_update_elem(&in_readahead, &pid, &one, 0);
	return 0;
}

static int do_page_cache_ra_ret(void)
{
	u32 pid = bpf_get_current_pid_tgid();

	bpf_map_delete_elem(&in_readahead, &pid);
	return 0;
}

SEC("fentry/do_page_cache_ra")
int BPF_PROG(fentry_do_page_cache_ra)
{
	return do_page_cache_ra();
}

SEC("fexit/__page_cache_alloc")
int BPF_PROG(fexit_page_cache_alloc, gfp_t gfp, struct page *ret)
{
	return do_page_cache_alloc_ret(ret);
}

SEC("fexit/do_page_cache_ra")
int BPF_PROG(fexit_do_page_cache_ra)
{
	return do_page_cache_ra_ret();
}

SEC("fentry/mark_page_accessed")
int BPF_PROG(fentry_mark_page_accessed, struct page *page)
{
	return do_mark_page_accessed(page);
}

SEC("kprobe/do_page_cache_ra")
int BPF_KPROBE(kprobe_do_page_cache_ra)
{
	return do_page_cache_ra();
}

SEC("kretprobe/do_page_cache_ra")
int BPF_KRETPROBE(kretprobe_do_page_cache_ra)
{
	return do_page_cache_ra_ret();
}

SEC("kprobe/__do_page_cache_readahead")
int BPF_KPROBE(kprobe___do_page_cache_readahead)
{
	return do_page_cache_ra();
}

SEC("kretprobe/__do_page_cache_readahead")
int BPF_KRETPROBE(kretprobe___do_page_cache_readahead)
{
	return do_page_cache_ra_ret();
}

SEC("kretprobe/__page_cache_alloc")
int BPF_KRETPROBE(kretprobe_page_cache_alloc, struct page *ret)
{
	return do_page_cache_alloc_ret(ret);
}

SEC("kprobe/mark_page_accessed")
int BPF_KPROBE(kprobe_mark_page_accessed, struct page *page)
{
	return do_mark_page_accessed(page);
}

char LICENSE[] SEC("license") = "GPL";

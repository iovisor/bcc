// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

__s64 total = 0;	/* total cache accesses without counting dirties */
__s64 misses = 0;	/* total of add to lru because of read misses */
__u64 mbd = 0;  	/* total of mark_buffer_dirty events */

SEC("fentry/add_to_page_cache_lru")
int BPF_PROG(fentry_add_to_page_cache_lru)
{
	__sync_fetch_and_add(&misses, 1);
	return 0;
}

SEC("fentry/mark_page_accessed")
int BPF_PROG(fentry_mark_page_accessed)
{
	__sync_fetch_and_add(&total, 1);
	return 0;
}

SEC("fentry/account_page_dirtied")
int BPF_PROG(fentry_account_page_dirtied)
{
	__sync_fetch_and_add(&misses, -1);
	return 0;
}

SEC("fentry/mark_buffer_dirty")
int BPF_PROG(fentry_mark_buffer_dirty)
{
	__sync_fetch_and_add(&total, -1);
	__sync_fetch_and_add(&mbd, 1);
	return 0;
}

SEC("kprobe/add_to_page_cache_lru")
int BPF_KPROBE(kprobe_add_to_page_cache_lru)
{
	__sync_fetch_and_add(&misses, 1);
	return 0;
}

SEC("kprobe/mark_page_accessed")
int BPF_KPROBE(kprobe_mark_page_accessed)
{
	__sync_fetch_and_add(&total, 1);
	return 0;
}

SEC("kprobe/account_page_dirtied")
int BPF_KPROBE(kprobe_account_page_dirtied)
{
	__sync_fetch_and_add(&misses, -1);
	return 0;
}

SEC("kprobe/folio_account_dirtied")
int BPF_KPROBE(kprobe_folio_account_dirtied)
{
	__sync_fetch_and_add(&misses, -1);
	return 0;
}

SEC("kprobe/mark_buffer_dirty")
int BPF_KPROBE(kprobe_mark_buffer_dirty)
{
	__sync_fetch_and_add(&total, -1);
	__sync_fetch_and_add(&mbd, 1);
	return 0;
}

SEC("tracepoint/writeback/writeback_dirty_folio")
int tracepoint__writeback_dirty_folio(struct trace_event_raw_sys_enter* ctx)
{
	__sync_fetch_and_add(&misses, -1);
	return 0;
}

SEC("tracepoint/writeback/writeback_dirty_page")
int tracepoint__writeback_dirty_page(struct trace_event_raw_sys_enter* ctx)
{
	__sync_fetch_and_add(&misses, -1);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

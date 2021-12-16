// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

__s64 total = 0;	/* total cache accesses without counting dirties */
__s64 misses = 0;	/* total of add to lru because of read misses */
__u64 mbd = 0;  	/* total of mark_buffer_dirty events */

SEC("fentry/add_to_page_cache_lru")
int BPF_PROG(add_to_page_cache_lru)
{
	__sync_fetch_and_add(&misses, 1);
	return 0;
}

SEC("fentry/mark_page_accessed")
int BPF_PROG(mark_page_accessed)
{
	__sync_fetch_and_add(&total, 1);
	return 0;
}

SEC("fentry/account_page_dirtied")
int BPF_PROG(account_page_dirtied)
{
	__sync_fetch_and_add(&misses, -1);
	return 0;
}

SEC("fentry/mark_buffer_dirty")
int BPF_PROG(mark_buffer_dirty)
{
	__sync_fetch_and_add(&total, -1);
	__sync_fetch_and_add(&mbd, 1);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

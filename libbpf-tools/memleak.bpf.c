// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Hengqi Chen
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "memleak.h"

#define MAX_ENTRIES 10240
#define MAX_ALLOC_ENTRIES 1000000

const volatile bool filter_min_size = false;
const volatile bool filter_max_size = false;
const volatile size_t min_size = 0;
const volatile size_t max_size = 1UL << 32;

const volatile int sample_rate = 1;
const volatile bool debug_enabled = false;
const volatile int page_size = 4096;
const volatile int stack_flags = 0;

const volatile bool missing_free = false;

struct mm_page_free_ctx {
	__u64 __padding;
	unsigned long pfn;      // offset:8;       size:8; signed:0;
};

struct mm_page_alloc_ctx {
	__u64 __padding;
	unsigned long pfn;      // offset:8;       size:8; signed:0;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, __u64);
} sizes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ALLOC_ENTRIES);
	__type(key, __u64);
	__type(value, struct alloc_info_t);
} allocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, __u64);
} memptrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(__u32));
} stack_traces SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct combined_alloc_info_t);
} combined_allocs SEC(".maps");

static void incr_stat(__u64 stack_id, __u64 sz) {
	struct combined_alloc_info_t *existing_cinfo;
	struct combined_alloc_info_t cinfo = {0};

	existing_cinfo = bpf_map_lookup_elem(&combined_allocs, &stack_id);
	if (existing_cinfo) {
		cinfo = *existing_cinfo;
	}

	cinfo.total_size += sz;
	cinfo.number_of_allocs += 1;
	bpf_map_update_elem(&combined_allocs, &stack_id, &cinfo, BPF_ANY);
}

static void decr_stat(__u64 stack_id, __u64 sz) {
	struct combined_alloc_info_t *existing_cinfo;
	struct combined_alloc_info_t cinfo = {0};

	existing_cinfo = bpf_map_lookup_elem(&combined_allocs, &stack_id);
	if (existing_cinfo) {
		cinfo = *existing_cinfo;
	}

	if (sz >= cinfo.total_size) {
		cinfo.total_size = 0;
	} else {
		cinfo.total_size -= sz;
	}
	if (cinfo.number_of_allocs > 0) {
		cinfo.number_of_allocs -= 1;
	}
	bpf_map_update_elem(&combined_allocs, &stack_id, &cinfo, BPF_ANY);
}

static int handle_free_entry(void *ptr) {
	__u64 addr = (__u64)ptr;
	struct alloc_info_t *info = bpf_map_lookup_elem(&allocs, &addr);

	if (!info) {
		return 0;
	}

	if (debug_enabled) {
		bpf_trace_printk("free entered, address = %lx, size = %lu\n", addr, info->size);
	}
	bpf_map_delete_elem(&allocs, &addr);
	decr_stat(info->stack_id, info->size);
	return 0;
}

static int handle_alloc_entry(size_t size) {
	if (filter_min_size && size < min_size) {
		return 0;
	}
	if (filter_max_size && size > max_size) {
		return 0;
	}
	if (sample_rate > 1) {
		__u64 ts = bpf_ktime_get_ns();
		if (ts % sample_rate != 0)
			return 0;
	}

	__u64 pid = bpf_get_current_pid_tgid();
	__u64 size64 = size;
	bpf_map_update_elem(&sizes, &pid, &size64, BPF_ANY);

	if (debug_enabled) {
		bpf_trace_printk("alloc entered, size = %u\n", size);
	}
	return 0;
}

static int handle_alloc_exit(void *ctx, __u64 addr) {
	__u64 pid = bpf_get_current_pid_tgid();
	__u64 *size64 = bpf_map_lookup_elem(&sizes, &pid);
	struct alloc_info_t info = {0};

	if (size64 == 0) {
		return 0; // missed alloc entry
	}

	info.size = *size64;
	bpf_map_delete_elem(&sizes, &pid);

	if (addr) {
		info.timestamp_ns = bpf_ktime_get_ns();
		info.stack_id = bpf_get_stackid(ctx, &stack_traces, stack_flags);
		bpf_map_update_elem(&allocs, &addr, &info, BPF_ANY);
		incr_stat(info.stack_id, info.size);
	}

	if (debug_enabled) {
		bpf_trace_printk("alloc exited, size = %lu, result = %lx\n", info.size, addr);
	}
	return 0;
}

SEC("tp_btf/kmalloc")
int BPF_PROG(kmalloc, unsigned long call_site, const void *ptr,
			size_t bytes_req, size_t bytes_alloc, gfp_t gfp_flags) {
	if (missing_free) {
		handle_free_entry((void *)ptr);
	}
	handle_alloc_entry(bytes_alloc);
	return handle_alloc_exit(ctx, (__u64)(void *)ptr);
}

SEC("tp_btf/kmalloc_node")
int BPF_PROG(kmalloc_node, unsigned long call_site, const void *ptr,
			size_t bytes_req, size_t bytes_alloc, gfp_t gfp_flags, int node) {
	if (missing_free) {
		handle_free_entry((void *)ptr);
	}
	handle_alloc_entry(bytes_alloc);
	return handle_alloc_exit(ctx, (__u64)(void *)ptr);
}

// SEC("tp_btf/kfree")
// int BPF_PROG(kfree, unsigned long call_site, const void *ptr) {
// 	return handle_free_entry((void *)ptr);
// }

// SEC("tp_btf/kmem_cache_alloc")
// int BPF_PROG(kmem_cache_alloc, unsigned long call_site, const void *ptr,
// 			size_t bytes_req, size_t bytes_alloc, gfp_t gfp_flags) {
// 	if (missing_free) {
// 		handle_free_entry((void *)ptr);
// 	}
// 	handle_alloc_entry(bytes_alloc);
// 	return handle_alloc_exit(ctx, (__u64)(void *)ptr);
// }

// SEC("tp_btf/kmem_cache_alloc_node")
// int BPF_PROG(kmem_cache_alloc_node, unsigned long call_site, const void *ptr,
// 			size_t bytes_req, size_t bytes_alloc, gfp_t gfp_flags, int node) {
// 	if (missing_free) {
// 		handle_free_entry((void *)ptr);
// 	}
// 	handle_alloc_entry(bytes_alloc);
// 	return handle_alloc_exit(ctx, (__u64)(void *)ptr);
// }

// SEC("tp_btf/kmem_cache_free")
// int BPF_PROG(kmem_cache_free, unsigned long call_site, const void *ptr, const char *name) {
// 	return handle_free_entry((void *)ptr);
// }

// SEC("tp_btf/mm_page_alloc")
// int BPF_PROG(mm_page_alloc, struct page *page, unsigned int order, gfp_t gfp_flags, int migratetype) {
// 	handle_alloc_entry(page_size << order);
// 	struct mm_page_alloc_ctx *args = (struct mm_page_alloc_ctx *)ctx;
// 	return handle_alloc_exit(ctx, args->pfn);
// }

// SEC("tp_btf/mm_page_free")
// int BPF_PROG(mm_page_free, struct page *page, unsigned int order) {
// 	struct mm_page_free_ctx *args = (struct mm_page_free_ctx *)ctx;
// 	return handle_free_entry((void *)args->pfn);
// }

// SEC("tp_btf/percpu_alloc_percpu")
// int BPF_PROG(percpu_alloc_percpu, bool reserved, bool is_atomic, size_t size,
// 			size_t align, void *base_addr, int off, void *ptr) {
// 	handle_alloc_entry(size);
// 	return handle_alloc_exit(ctx, (__u64)ptr);
// }

// SEC("tp_btf/percpu_free_percpu")
// int BPF_PROG(percpu_free_percpu, void *base_addr, int off, void *ptr) {
// 	return handle_free_entry(ptr);
// }

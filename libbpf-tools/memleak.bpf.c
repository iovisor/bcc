// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "maps.bpf.h"
#include "memleak.h"
#include "core_fixes.bpf.h"

const volatile size_t min_size = 0;
const volatile size_t max_size = -1;
const volatile size_t page_size = 4096;
const volatile __u64 sample_rate = 1;
const volatile bool trace_all = false;
const volatile __u64 stack_flags = 0;
const volatile bool wa_missing_free = false;
const volatile bool combined_only = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 10240);
} sizes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); /* address */
	__type(value, struct alloc_info);
	__uint(max_entries, ALLOCS_MAX_ENTRIES);
} allocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); /* stack id */
	__type(value, union combined_alloc_info);
	__uint(max_entries, 1);
} combined_allocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 10240);
} memptrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
} stack_traces SEC(".maps");

static union combined_alloc_info initial_cinfo;

static void update_statistics_add(u64 stack_id, u64 sz)
{
	union combined_alloc_info *existing_cinfo;

	existing_cinfo = bpf_map_lookup_or_try_init(&combined_allocs, &stack_id, &initial_cinfo);
	if (!existing_cinfo)
		return;

	const union combined_alloc_info incremental_cinfo = {
		.total_size = sz,
		.number_of_allocs = 1
	};

	__sync_fetch_and_add(&existing_cinfo->bits, incremental_cinfo.bits);
}

static void update_statistics_del(u64 stack_id, u64 sz)
{
	union combined_alloc_info *existing_cinfo;

	existing_cinfo = bpf_map_lookup_elem(&combined_allocs, &stack_id);
	if (!existing_cinfo) {
		bpf_printk("failed to lookup combined allocs\n");

		return;
	}

	const union combined_alloc_info decremental_cinfo = {
		.total_size = sz,
		.number_of_allocs = 1
	};

	__sync_fetch_and_sub(&existing_cinfo->bits, decremental_cinfo.bits);
}

static int gen_alloc_enter(size_t size)
{
	if (size < min_size || size > max_size)
		return 0;

	if (sample_rate > 1) {
		if (bpf_ktime_get_ns() % sample_rate != 0)
			return 0;
	}

	const u32 tid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&sizes, &tid, &size, BPF_ANY);

	if (trace_all)
		bpf_printk("alloc entered, size = %lu\n", size);

	return 0;
}

static int gen_alloc_exit2(void *ctx, u64 address)
{
	const u32 tid = bpf_get_current_pid_tgid();
	struct alloc_info info;

	const u64* size = bpf_map_lookup_elem(&sizes, &tid);
	if (!size)
		return 0; // missed alloc entry

	__builtin_memset(&info, 0, sizeof(info));

	info.size = *size;
	bpf_map_delete_elem(&sizes, &tid);

	if (address != 0 && address != MAP_FAILED) {
		info.timestamp_ns = bpf_ktime_get_ns();

		info.stack_id = bpf_get_stackid(ctx, &stack_traces, stack_flags);

		bpf_map_update_elem(&allocs, &address, &info, BPF_ANY);

		if (combined_only)
			update_statistics_add(info.stack_id, info.size);
	}

	if (trace_all) {
		bpf_printk("alloc exited, size = %lu, result = %lx\n",
				info.size, address);
	}

	return 0;
}

static int gen_alloc_exit(struct pt_regs *ctx)
{
	return gen_alloc_exit2(ctx, PT_REGS_RC(ctx));
}

static int gen_free_enter(const void *address)
{
	const u64 addr = (u64)address;

	const struct alloc_info *info = bpf_map_lookup_elem(&allocs, &addr);
	if (!info)
		return 0;

	bpf_map_delete_elem(&allocs, &addr);

	if (combined_only)
		update_statistics_del(info->stack_id, info->size);

	if (trace_all) {
		bpf_printk("free entered, address = %lx, size = %lu\n",
				address, info->size);
	}

	return 0;
}

SEC("uprobe")
int BPF_UPROBE(malloc_enter, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(malloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_UPROBE(free_enter, void *address)
{
	return gen_free_enter(address);
}

SEC("uprobe")
int BPF_UPROBE(calloc_enter, size_t nmemb, size_t size)
{
	return gen_alloc_enter(nmemb * size);
}

SEC("uretprobe")
int BPF_URETPROBE(calloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_UPROBE(realloc_enter, void *ptr, size_t size)
{
	gen_free_enter(ptr);

	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(realloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_UPROBE(mmap_enter, void *address, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(mmap_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_UPROBE(munmap_enter, void *address)
{
	return gen_free_enter(address);
}

SEC("uprobe")
int BPF_UPROBE(mremap_enter, void *old_address, size_t old_size, size_t new_size, int flags)
{
	gen_free_enter(old_address);

	return gen_alloc_enter(new_size);
}

SEC("uretprobe")
int BPF_URETPROBE(mremap_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_UPROBE(posix_memalign_enter, void **memptr, size_t alignment, size_t size)
{
	const u64 memptr64 = (u64)(size_t)memptr;
	const u32 tid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&memptrs, &tid, &memptr64, BPF_ANY);

	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(posix_memalign_exit)
{
	u64 *memptr64;
	void *addr;
	const u32 tid = bpf_get_current_pid_tgid();

	memptr64 = bpf_map_lookup_elem(&memptrs, &tid);
	if (!memptr64)
		return 0;

	bpf_map_delete_elem(&memptrs, &tid);

	if (bpf_probe_read_user(&addr, sizeof(void*), (void*)(size_t)*memptr64))
		return 0;

	const u64 addr64 = (u64)(size_t)addr;

	return gen_alloc_exit2(ctx, addr64);
}

SEC("uprobe")
int BPF_UPROBE(aligned_alloc_enter, size_t alignment, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(aligned_alloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_UPROBE(valloc_enter, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(valloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_UPROBE(memalign_enter, size_t alignment, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(memalign_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_UPROBE(pvalloc_enter, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(pvalloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("tracepoint/kmem/kmalloc")
int memleak__kmalloc(void *ctx)
{
	const void *ptr;
	size_t bytes_alloc;

	if (has_kmem_alloc()) {
		struct trace_event_raw_kmem_alloc___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
	} else {
		struct trace_event_raw_kmalloc___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
	}

	if (wa_missing_free)
		gen_free_enter(ptr);

	gen_alloc_enter(bytes_alloc);

	return gen_alloc_exit2(ctx, (u64)ptr);
}

SEC("tracepoint/kmem/kmalloc_node")
int memleak__kmalloc_node(void *ctx)
{
	const void *ptr;
	size_t bytes_alloc;

	if (has_kmem_alloc_node()) {
		struct trace_event_raw_kmem_alloc_node___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);

		if (wa_missing_free)
			gen_free_enter(ptr);

		gen_alloc_enter( bytes_alloc);

		return gen_alloc_exit2(ctx, (u64)ptr);
	} else {
		/* tracepoint is disabled if not exist, avoid compile warning */
		return 0;
	}
}

SEC("tracepoint/kmem/kfree")
int memleak__kfree(void *ctx)
{
	const void *ptr;

	if (has_kfree()) {
		struct trace_event_raw_kfree___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	} else {
		struct trace_event_raw_kmem_free___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	}

	return gen_free_enter(ptr);
}

SEC("tracepoint/kmem/kmem_cache_alloc")
int memleak__kmem_cache_alloc(void *ctx)
{
	const void *ptr;
	size_t bytes_alloc;

	if (has_kmem_alloc()) {
		struct trace_event_raw_kmem_alloc___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
	} else {
		struct trace_event_raw_kmem_cache_alloc___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
	}

	if (wa_missing_free)
		gen_free_enter(ptr);

	gen_alloc_enter(bytes_alloc);

	return gen_alloc_exit2(ctx, (u64)ptr);
}

SEC("tracepoint/kmem/kmem_cache_alloc_node")
int memleak__kmem_cache_alloc_node(void *ctx)
{
	const void *ptr;
	size_t bytes_alloc;

	if (has_kmem_alloc_node()) {
		struct trace_event_raw_kmem_alloc_node___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);

		if (wa_missing_free)
			gen_free_enter(ptr);

		gen_alloc_enter(bytes_alloc);

		return gen_alloc_exit2(ctx, (u64)ptr);
	} else {
		/* tracepoint is disabled if not exist, avoid compile warning */
		return 0;
	}
}

SEC("tracepoint/kmem/kmem_cache_free")
int memleak__kmem_cache_free(void *ctx)
{
	const void *ptr;

	if (has_kmem_cache_free()) {
		struct trace_event_raw_kmem_cache_free___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	} else {
		struct trace_event_raw_kmem_free___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	}

	return gen_free_enter(ptr);
}

SEC("tracepoint/kmem/mm_page_alloc")
int memleak__mm_page_alloc(struct trace_event_raw_mm_page_alloc *ctx)
{
	gen_alloc_enter(page_size << ctx->order);

	return gen_alloc_exit2(ctx, ctx->pfn);
}

SEC("tracepoint/kmem/mm_page_free")
int memleak__mm_page_free(struct trace_event_raw_mm_page_free *ctx)
{
	return gen_free_enter((void *)ctx->pfn);
}

SEC("tracepoint/percpu/percpu_alloc_percpu")
int memleak__percpu_alloc_percpu(struct trace_event_raw_percpu_alloc_percpu *ctx)
{
	gen_alloc_enter(ctx->bytes_alloc);

	return gen_alloc_exit2(ctx, (u64)(ctx->ptr));
}

SEC("tracepoint/percpu/percpu_free_percpu")
int memleak__percpu_free_percpu(struct trace_event_raw_percpu_free_percpu *ctx)
{
	return gen_free_enter(ctx->ptr);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// SPDX-License-Identifier: GPL-2.0
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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t);
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
	__uint(max_entries, COMBINED_ALLOCS_MAX_ENTRIES);
} combined_allocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
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

	const pid_t pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&sizes, &pid, &size, BPF_ANY);

	if (trace_all)
		bpf_printk("alloc entered, size = %lu\n", size);

	return 0;
}

static int gen_alloc_exit2(void *ctx, u64 address)
{
	const pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct alloc_info info;

	const u64* size = bpf_map_lookup_elem(&sizes, &pid);
	if (!size)
		return 0; // missed alloc entry

	__builtin_memset(&info, 0, sizeof(info));

	info.size = *size;
	bpf_map_delete_elem(&sizes, &pid);

	if (address != 0) {
		info.timestamp_ns = bpf_ktime_get_ns();

		info.stack_id = bpf_get_stackid(ctx, &stack_traces, stack_flags);

		bpf_map_update_elem(&allocs, &address, &info, BPF_ANY);

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
	update_statistics_del(info->stack_id, info->size);

	if (trace_all) {
		bpf_printk("free entered, address = %lx, size = %lu\n",
				address, info->size);
	}

	return 0;
}

SEC("uprobe")
int BPF_KPROBE(malloc_enter, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(malloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(free_enter, void *address)
{
	return gen_free_enter(address);
}

SEC("uprobe")
int BPF_KPROBE(calloc_enter, size_t nmemb, size_t size)
{
	return gen_alloc_enter(nmemb * size);
}

SEC("uretprobe")
int BPF_KRETPROBE(calloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(realloc_enter, void *ptr, size_t size)
{
	gen_free_enter(ptr);

	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(realloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(mmap_enter, void *address, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(mmap_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(munmap_enter, void *address)
{
	return gen_free_enter(address);
}

SEC("uprobe")
int BPF_KPROBE(posix_memalign_enter, void **memptr, size_t alignment, size_t size)
{
	const u64 memptr64 = (u64)(size_t)memptr;
	const u64 pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&memptrs, &pid, &memptr64, BPF_ANY);

	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(posix_memalign_exit)
{
	const u64 pid = bpf_get_current_pid_tgid() >> 32;
	u64 *memptr64;
	void *addr;

	memptr64 = bpf_map_lookup_elem(&memptrs, &pid);
	if (!memptr64)
		return 0;

	bpf_map_delete_elem(&memptrs, &pid);

	if (bpf_probe_read_user(&addr, sizeof(void*), (void*)(size_t)*memptr64))
		return 0;

	const u64 addr64 = (u64)(size_t)addr;

	return gen_alloc_exit2(ctx, addr64);
}

SEC("uprobe")
int BPF_KPROBE(aligned_alloc_enter, size_t alignment, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(aligned_alloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(valloc_enter, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(valloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(memalign_enter, size_t alignment, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(memalign_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(pvalloc_enter, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(pvalloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("tracepoint/kmem/kmalloc")
int memleak__kmalloc(struct trace_event_raw_kmem_alloc *ctx)
{
	if (wa_missing_free)
		gen_free_enter(ctx->ptr);

	gen_alloc_enter(ctx->bytes_alloc);

	return gen_alloc_exit2(ctx, (u64)(ctx->ptr));
}

SEC("tracepoint/kmem/kmalloc_node")
int memleak__kmalloc_node(struct trace_event_raw_kmem_alloc_node *ctx)
{
	if (wa_missing_free)
		gen_free_enter(ctx->ptr);

	gen_alloc_enter(ctx->bytes_alloc);

	return gen_alloc_exit2(ctx, (u64)(ctx->ptr));
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
int memleak__kmem_cache_alloc(struct trace_event_raw_kmem_alloc *ctx)
{
	if (wa_missing_free)
		gen_free_enter(ctx->ptr);

	gen_alloc_enter(ctx->bytes_alloc);

	return gen_alloc_exit2(ctx, (u64)(ctx->ptr));
}

SEC("tracepoint/kmem/kmem_cache_alloc_node")
int memleak__kmem_cache_alloc_node(struct trace_event_raw_kmem_alloc_node *ctx)
{
	if (wa_missing_free)
		gen_free_enter(ctx->ptr);

	gen_alloc_enter(ctx->bytes_alloc);

	return gen_alloc_exit2(ctx, (u64)(ctx->ptr));
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

char LICENSE[] SEC("license") = "GPL";

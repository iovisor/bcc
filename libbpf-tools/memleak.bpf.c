// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Jackie Dinh
//
// Based on memleak(8) from BCC by Sasha Goldshtein
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "memleak.h"

char LICENSE[] SEC("license") = "GPL";

const volatile size_t min_size = 0;
const volatile size_t max_size = 1UL << 32;
const volatile int sample_rate = 1;
const volatile bool trace_all = false;
const volatile long page_size = 4096;
const volatile int stack_flags = 0;
const volatile bool wa_missing_free = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_HASH_ENTRY_NUM);
	__type(key, __u64);
	__type(value, __u64);
} sizes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_HASH_ENTRY_NUM);
	__type(key, __u64);
	__type(value, struct alloc_info_t);
} allocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_HASH_ENTRY_NUM);
	__type(key, __u64);
	__type(value, __u64);
} memptrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(__u32));
} stack_traces SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_HASH_ENTRY_NUM);
	__type(key, __u64);
	__type(value, struct combined_alloc_info_t);
} combined_allocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} alloc_counters SEC(".maps");

static __always_inline void update_statistics_add(__u64 stack_id, __u64 sz) {
	struct combined_alloc_info_t *existing_cinfo;
	struct combined_alloc_info_t cinfo = {0};

	existing_cinfo = bpf_map_lookup_elem(&combined_allocs, &stack_id);
	if (existing_cinfo != 0) {
		cinfo = *existing_cinfo;
	}

	cinfo.total_size += sz;
	cinfo.number_of_allocs += 1;
	bpf_map_update_elem(&combined_allocs, &stack_id, &cinfo, BPF_ANY);
}

static __always_inline void update_statistics_del(__u64 stack_id, __u64 sz) {
	struct combined_alloc_info_t *existing_cinfo;
	struct combined_alloc_info_t cinfo = {0};

	existing_cinfo = bpf_map_lookup_elem(&combined_allocs, &stack_id);
	if (existing_cinfo != 0) {
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

static __always_inline int gen_alloc_enter(struct pt_regs *ctx, size_t size) {
	__u64 pid = bpf_get_current_pid_tgid();
	__u64 size64 = size;

	if (min_size > 0 && size < min_size) {
		return 0;
	}

	if (max_size > 0 && size > max_size) {
		return 0;
	}

	if (sample_rate > 1) {
		__u64 key = 0;
		__u64 *cnt;
		cnt = bpf_map_lookup_elem(&alloc_counters, &key);
		if (cnt == NULL) {
			return 0;
		}
		*cnt += 1;
		if (*cnt % sample_rate != 0) {
			return 0;
		}
	}

	bpf_map_update_elem(&sizes, &pid, &size64, BPF_ANY);

	if (trace_all) {
		bpf_printk("alloc entered, size=%u\n", size);
	}
	return 0;
}

static __always_inline int gen_alloc_exit(struct pt_regs *ctx, __u64 address) {
	__u64  pid = bpf_get_current_pid_tgid();
	__u64* size64 = bpf_map_lookup_elem(&sizes, &pid);
	struct alloc_info_t info = {0};

	if (size64 == 0) {
		return 0;
	}

	info.size = *size64;
	bpf_map_delete_elem(&sizes, &pid);

	if (address != 0) {
		info.timestamp_ns = bpf_ktime_get_ns();
		info.stack_id = bpf_get_stackid(ctx, &stack_traces, stack_flags);
		if (info.stack_id < 0)
			return 0;
		bpf_map_update_elem(&allocs, &address, &info, BPF_ANY);
		update_statistics_add(info.stack_id, info.size);
	}

	if (trace_all) {
		bpf_printk("alloc exited, size = %llu, result = %llx\n", info.size, address);
	}
	return 0;
}

static __always_inline int gen_free_enter(struct pt_regs *ctx, void *address) {
	__u64 addr = (__u64)address;
	struct alloc_info_t *info = bpf_map_lookup_elem(&allocs, &addr);
	if (info == 0) {
		return 0;
	}

	bpf_map_delete_elem(&allocs, &addr);
	update_statistics_del(info->stack_id, info->size);

	if (trace_all) {
	  bpf_printk("free entered, address = %lx, size = %lu\n", addr, info->size);
	}
	return 0;
}

SEC("uprobe/malloc")
int BPF_KPROBE(uprobe_malloc, size_t size)
{
	return gen_alloc_enter(ctx, size);
}

SEC("uretprobe/malloc")
int BPF_KRETPROBE(uretprobe_malloc, void *ret)
{
	return gen_alloc_exit(ctx, (uint64_t)ret);
}

SEC("uprobe/calloc")
int BPF_KPROBE(uprobe_calloc, size_t nmemb, size_t size)
{
	gen_alloc_enter(ctx, nmemb*size);
	return 0;
}

SEC("uretprobe/calloc")
int BPF_KRETPROBE(uretprobe_calloc, void *ret)
{
	gen_alloc_exit(ctx, PT_REGS_RC(ctx));
	return 0;
}

SEC("uprobe/realloc")
int BPF_KPROBE(uprobe_realloc, void *ptr, size_t size)
{
	/* Delete old allocation */
	gen_free_enter(ctx, ptr);
	gen_alloc_enter(ctx, size);
	return 0;
}

SEC("uretprobe/realloc")
int BPF_KRETPROBE(uretprobe_realloc, void *ret)
{
	gen_alloc_exit(ctx, PT_REGS_RC(ctx));
	return 0;
}

SEC("uprobe/memalign")
int BPF_KPROBE(uprobe_memalign, size_t alignment, size_t size)
{
	return gen_alloc_enter(ctx, size);
}

SEC("uretprobe/memalign")
int BPF_KRETPROBE(uretprobe_memalign, void *ret)
{
	return gen_alloc_exit(ctx, (uint64_t)ret);
}

SEC("uprobe/posix_memalign")
int BPF_KPROBE(uprobe_posix_memalign, void **memptr, size_t alignment, size_t size)
{
	__u64 memptr64 = (__u64)(size_t)memptr;
	__u64 pid = bpf_get_current_pid_tgid();

	bpf_map_update_elem(&memptrs, &pid, &memptr64, BPF_ANY);
	return gen_alloc_enter(ctx, size);
}

SEC("uretprobe/posix_memalign")
int BPF_KRETPROBE(uretprobe_posix_memalign, void *ret)
{
	__u64 pid = bpf_get_current_pid_tgid();
	__u64 *memptr64 = bpf_map_lookup_elem(&memptrs, &pid);
	__u64 addr64;
	void *addr;

	if (memptr64 == 0) {
		return 0;
	}

	bpf_map_delete_elem(&memptrs, &pid);
	if (bpf_probe_read_user(&addr, sizeof(void*), (void*)(size_t)*memptr64)) {
		return 0;
	}

	addr64 = (u64)(size_t)addr;
	return gen_alloc_exit(ctx, addr64);
}

SEC("uprobe/valloc")
int BPF_KPROBE(uprobe_valloc, size_t size)
{
	return gen_alloc_enter(ctx, size);
}

SEC("uretprobe/valloc")
int BPF_KRETPROBE(uretprobe_valloc, void *ret)
{
	return gen_alloc_exit(ctx, (uint64_t)ret);
}

SEC("uprobe/pvalloc")
int BPF_KPROBE(uprobe_pvalloc, size_t size)
{
	return gen_alloc_enter(ctx, size);
}

SEC("uretprobe/pvalloc")
int BPF_KRETPROBE(uretprobe_pvalloc, void *ret)
{
	return gen_alloc_exit(ctx, (uint64_t)ret);
}

SEC("uprobe/aligned_alloc")
int BPF_KPROBE(uprobe_aligned_alloc, size_t alignment, size_t size)
{
	return gen_alloc_enter(ctx, size);
}

SEC("uretprobe/aligned_alloc")
int BPF_KRETPROBE(uretprobe_aligned_alloc, void *ret)
{
	return gen_alloc_exit(ctx, (uint64_t)ret);
}

SEC("uprobe/free")
int BPF_KPROBE(uprobe_free, void *addr)
{
   return gen_free_enter(ctx, addr);
}

SEC("tracepoint/kmem/kmalloc")
int tracepoint_kmalloc(struct trace_event_raw_kmem_alloc *args)
{
	if (wa_missing_free) {
		gen_free_enter((struct pt_regs*)args, (void *)args->ptr);
	}
	gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc);
	return gen_alloc_exit((struct pt_regs*)args, (__u64)args->ptr);
}

SEC("tracepoint/kmem/kfree")
int tracepoint_kfree(struct trace_event_raw_kmem_free *args)
{
	return gen_free_enter((struct pt_regs*)args, (void *)args->ptr);
}

SEC("tracepoint/kmem/kmalloc_node")
int tracepoint_kmalloc_node(struct trace_event_raw_kmem_alloc_node *args)
{
	if (wa_missing_free) {
		gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
	}
	gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc);
	return gen_alloc_exit((struct pt_regs*)args, (__u64)args->ptr);
}

SEC("tracepoint/kmem/kmem_cache_alloc")
int tracepoint_kmem_cache_alloc(struct trace_event_raw_kmem_alloc *args)
{
	if (wa_missing_free) {
		gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
	}
	gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc);
	return gen_alloc_exit((struct pt_regs*)args, (__u64)args->ptr);
}

SEC("tracepoint/kmem/kmem_cache_alloc_node")
int tracepoint_kmem_cache_alloc_node(struct trace_event_raw_kmem_alloc_node *args)
{
	if (wa_missing_free) {
		gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
	}
	gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc);
	return gen_alloc_exit((struct pt_regs*)args, (__u64)args->ptr);
}

SEC("tracepoint/kmem/kmem_cache_free")
int tracepoint_kmem_cache_free(struct trace_event_raw_kmem_free *args)
{
	return gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
}

SEC("tracepoint/kmem/mm_page_alloc")
int tracepoint_mm_page_alloc(struct trace_event_raw_mm_page_alloc *args)
{
	gen_alloc_enter((struct pt_regs *)args, page_size << args->order);
	return gen_alloc_exit((struct pt_regs*)args, args->pfn);
}

SEC("tracepoint/kmem/mm_page_free")
int tracepoint_mm_page_free(struct trace_event_raw_mm_page_free *args)
{
	return gen_free_enter((struct pt_regs*)args, (void *)args->pfn);
}

SEC("tracepoint/percpu/percpu_alloc_percpu")
int tracepoint_percpu_alloc_percpu(struct trace_event_raw_percpu_alloc_percpu *args)
{
	gen_alloc_enter((struct pt_regs *)args, args->size);
	return gen_alloc_exit((struct pt_regs*)args, (__u64)args->ptr);
}

SEC("tracepoint/percpu/percpu_free_percpu")
int tracepoint_percpu_free_percpu(struct trace_event_raw_percpu_free_percpu *args)
{
	return gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
}

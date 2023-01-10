#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "memleak.h"

const volatile pid_t pid = -1;
const volatile size_t min_size = 0;
const volatile size_t max_size = -1;
const volatile size_t page_size = 0; // todo - default?
const volatile __u64 sample_every_n = 1;
const volatile bool trace_all = false;
const volatile bool kernel_trace = false;
const volatile bool wa_missing_free = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 10240);
} sizes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, alloc_info_t);
	__uint(max_entries, 1000000);
} allocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u64);
	__uint(max_entries, 10240);
} memptrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, combined_alloc_info_t);
	__uint(max_entries, 10240);
} combined_allocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
} stack_traces SEC(".maps");


static __always_inline void update_statistics_add(u64 stack_id, u64 sz) {
	combined_alloc_info_t *existing_cinfo;
	combined_alloc_info_t cinfo = {0};

	existing_cinfo = bpf_map_lookup_elem(&combined_allocs, &stack_id);
	if (existing_cinfo)
		cinfo = *existing_cinfo;

	cinfo.total_size += sz;
	cinfo.number_of_allocs += 1;
	bpf_map_update_elem(&combined_allocs, &stack_id, &cinfo, BPF_ANY); // todo - flags?
}

static __always_inline void update_statistics_del(u64 stack_id, u64 sz) {
	combined_alloc_info_t *existing_cinfo;
	combined_alloc_info_t cinfo = {0};

	existing_cinfo = bpf_map_lookup_elem(&combined_allocs, &stack_id);
	if (existing_cinfo)
		cinfo = *existing_cinfo;

	if (sz >= cinfo.total_size)
		cinfo.total_size = 0;
	else
		cinfo.total_size -= sz;

	if (cinfo.number_of_allocs > 0)
		cinfo.number_of_allocs -= 1;

	bpf_map_update_elem(&combined_allocs, &stack_id, &cinfo, BPF_ANY); // todo - flags?
}

static __always_inline int gen_alloc_enter(struct pt_regs *ctx, size_t size)
{
	if (size < min_size || size > max_size)
		return 0;

	if (sample_every_n > 1) {
		const u64 ts = bpf_ktime_get_ns();
		if (ts % sample_every_n != 0) // todo - call in place
			return 0;
	}

	const u64 pid = bpf_get_current_pid_tgid();
	const u64 size64 = size;
	bpf_map_update_elem(&sizes, &pid, &size64, BPF_ANY); // todo - flags?

	if (trace_all)
		bpf_trace_printk("alloc entered, size = %u\\n", size);

	return 0;
}

static __always_inline int gen_alloc_exit2(struct pt_regs *ctx, u64 address) {
	const u64 pid = bpf_get_current_pid_tgid();
	const u64* size64 = bpf_map_lookup_elem(&sizes, &pid);
	alloc_info_t info = {0};
	int flags = 0;

	if (!size64)
		return 0; // missed alloc entry

	info.size = *size64;
	bpf_map_delete_elem(&sizes, &pid);

	if (address != 0) {
		info.timestamp_ns = bpf_ktime_get_ns();

		if (!kernel_trace)
			flags |= BPF_F_USER_STACK;

		info.stack_id = bpf_get_stackid(ctx, &stack_traces, flags); // todo - ternary

		bpf_map_update_elem(&allocs, &address, &info, BPF_ANY); // todo - flags?

		update_statistics_add(info.stack_id, info.size);
	}

	if (trace_all) {
		bpf_trace_printk("alloc exited, size = %lu, result = %lx\\n",
				info.size, address);
	}

	return 0;
}

static __always_inline int gen_alloc_exit(struct pt_regs *ctx) {
	return gen_alloc_exit2(ctx, PT_REGS_RC(ctx));
}

static __always_inline int gen_free_enter(struct pt_regs *ctx, void *address) {
	const u64 addr = (u64)address;
	const alloc_info_t *info = bpf_map_lookup_elem(&allocs, &addr);
	if (!info)
		return 0;

	bpf_map_delete_elem(&allocs, &addr);
	update_statistics_del(info->stack_id, info->size);

	if (trace_all) {
		bpf_trace_printk("free entered, address = %lx, size = %lu\\n",
				address, info->size); // todo - integer conversion?
	}
	return 0;
}

int malloc_enter(struct pt_regs *ctx, size_t size) {
	return gen_alloc_enter(ctx, size);
}

int malloc_exit(struct pt_regs *ctx) {
	return gen_alloc_exit(ctx);
}

int free_enter(struct pt_regs *ctx, void *address) {
	return gen_free_enter(ctx, address);
}

int calloc_enter(struct pt_regs *ctx, size_t nmemb, size_t size) {
	return gen_alloc_enter(ctx, nmemb * size);
}

int calloc_exit(struct pt_regs *ctx) {
	return gen_alloc_exit(ctx);
}

int realloc_enter(struct pt_regs *ctx, void *ptr, size_t size) {
	gen_free_enter(ctx, ptr);
	return gen_alloc_enter(ctx, size);
}

int realloc_exit(struct pt_regs *ctx) {
	return gen_alloc_exit(ctx);
}

int mmap_enter(struct pt_regs *ctx) {
	size_t size = (size_t)PT_REGS_PARM2(ctx);
	return gen_alloc_enter(ctx, size);
}

int mmap_exit(struct pt_regs *ctx) {
	return gen_alloc_exit(ctx);
}

int munmap_enter(struct pt_regs *ctx, void *address) {
	return gen_free_enter(ctx, address);
}

int posix_memalign_enter(struct pt_regs *ctx, void **memptr, size_t alignment,
		size_t size)
{
	const u64 memptr64 = (u64)(size_t)memptr;
	const u64 pid = bpf_get_current_pid_tgid();

	bpf_map_update_elem(&memptrs, &pid, &memptr64, BPF_ANY); // todo - flags?

	return gen_alloc_enter(ctx, size);
}

int posix_memalign_exit(struct pt_regs *ctx) {
	const u64 pid = bpf_get_current_pid_tgid();
	const u64 *memptr64;
	void *addr;

	memptr64 = bpf_map_lookup_elem(&memptrs, &pid);
	if (!memptr64)
		return 0;

	bpf_map_delete_elem(&memptrs, &pid);

	if (bpf_probe_read_user(&addr, sizeof(void*), (void*)(size_t)*memptr64))
		return 0;

	u64 addr64 = (u64)(size_t)addr;

	return gen_alloc_exit2(ctx, addr64);
}

int aligned_alloc_enter(struct pt_regs *ctx, size_t alignment, size_t size) {
	return gen_alloc_enter(ctx, size);
}

int aligned_alloc_exit(struct pt_regs *ctx) {
	return gen_alloc_exit(ctx);
}

int valloc_enter(struct pt_regs *ctx, size_t size) {
	return gen_alloc_enter(ctx, size);
}

int valloc_exit(struct pt_regs *ctx) {
	return gen_alloc_exit(ctx);
}

int memalign_enter(struct pt_regs *ctx, size_t alignment, size_t size) {
	return gen_alloc_enter(ctx, size);
}

int memalign_exit(struct pt_regs *ctx) {
	return gen_alloc_exit(ctx);
}

int pvalloc_enter(struct pt_regs *ctx, size_t size) {
	return gen_alloc_enter(ctx, size);
}

int pvalloc_exit(struct pt_regs *ctx) {
	return gen_alloc_exit(ctx);
}

SEC("tracepoint/kmem/kmalloc_node")
int tracepoint__kmalloc_node(const struct trace_event_raw_kmem_alloc_node *ctx)
{
	if (wa_missing_free)
		gen_free_enter((struct pt_regs *)ctx, (void *)ctx->ptr);

	gen_alloc_enter((struct pt_regs *)ctx, ctx->bytes_alloc);

	return gen_alloc_exit2((struct pt_regs *)ctx, (size_t)ctx->ptr);
}

SEC("tracepoint/kmem/kmem_cache_alloc_node")
int tracepoint__kmem_cache_alloc_node(const struct trace_event_raw_kmem_alloc_node *ctx) // todo type?
{
	if (wa_missing_free)
		gen_free_enter((struct pt_regs *)ctx, (void *)ctx->ptr);

	gen_alloc_enter((struct pt_regs *)ctx, ctx->bytes_alloc);

	return gen_alloc_exit2((struct pt_regs *)ctx, (size_t)ctx->ptr);
}

SEC("tracepoint/kmem/kmalloc")
int tracepoint__kmalloc(const struct trace_event_raw_kmem_alloc *ctx)
{
	if (wa_missing_free)
		gen_free_enter((struct pt_regs *)ctx, (void *)ctx->ptr);

	gen_alloc_enter((struct pt_regs *)ctx, ctx->bytes_alloc);

	return gen_alloc_exit2((struct pt_regs *)ctx, (size_t)ctx->ptr);
}

SEC("tracepoint/kmem/kfree")
int tracepoint__kfree(const struct trace_event_raw_kfree *ctx)
{
	return gen_free_enter((struct pt_regs *)ctx, (void *)ctx->ptr);
}

SEC("tracepoint/kmem/kmem_cache_alloc")
int tracepoint__kmem_cache_alloc(const struct trace_event_raw_kmem_alloc *ctx) // todo - type?
{
	if (wa_missing_free)
		gen_free_enter((struct pt_regs *)ctx, (void *)ctx->ptr);

	gen_alloc_enter((struct pt_regs *)ctx, ctx->bytes_alloc);

	return gen_alloc_exit2((struct pt_regs *)ctx, (size_t)ctx->ptr);
}

SEC("tracepoint/kmem/kmem_cache_free")
int tracepoint__kmem_cache_free(const struct trace_event_raw_kmem_cache_free *ctx)
{
	return gen_free_enter((struct pt_regs *)ctx, (void *)ctx->ptr);
}

SEC("tracepoint/kmem/mm_page_alloc")
int tracepoint__mm_page_alloc(const struct trace_event_raw_mm_page_alloc *ctx)
{
	gen_alloc_enter((struct pt_regs *)ctx, page_size << ctx->order);

	return gen_alloc_exit2((struct pt_regs *)ctx, ctx->pfn);
}

SEC("tracepoint/kmem/mm_page_free")
int tracepoint__mm_page_free(const struct trace_event_raw_mm_page_free *ctx)
{
	return gen_free_enter((struct pt_regs *)ctx, (void *)ctx->pfn);
}

/*
SEC("tracepoint/percpu/percpu_alloc_percpu")
int tracepoint__percpu_alloc_percpu(const struct trace_event_raw_percpu_alloc_percpu *ctx)
{
	gen_alloc_enter((struct pt_regs *)args, args->size);

	return gen_alloc_exit2((struct pt_regs *)args, (size_t)args->ptr);
}

SEC("tracepoint/percpu/percpu_free_percpu")
int tracepoint__percpu_free_percpu(const struct trace_event_raw_percpu_free_percpu *ctx)
{
	return gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
}
*/

char LICENSE[] SEC("license") = "GPL";

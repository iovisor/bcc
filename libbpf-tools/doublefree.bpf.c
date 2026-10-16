/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright 2022 LG Electronics Inc. */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "doublefree.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, u32);
	__type(value, u32);
} events SEC(".maps");

/* Addresses the target currently owns, keyed by address. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, int);
	__uint(max_entries, MAX_ENTRIES);
} allocs SEC(".maps");

/* Addresses the target has already handed back to the allocator. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct free_info);
	__uint(max_entries, MAX_ENTRIES);
} frees SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u64);
	__uint(max_entries, MAX_PENDING_CALLS);
} memptrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct realloc_info);
	__uint(max_entries, MAX_PENDING_CALLS);
} realloc_args SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
	__uint(max_entries, MAX_ENTRIES);
} stack_traces SEC(".maps");

static __always_inline void report(struct pt_regs *ctx, u64 addr,
				   int alloc_stackid, int free_stackid,
				   int doublefree_stackid)
{
	struct event event = {};

	event.addr = addr;
	event.alloc_stackid = alloc_stackid;
	event.free_stackid = free_stackid;
	event.doublefree_stackid = doublefree_stackid;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
			      sizeof(event));
}

static int gen_alloc_exit(struct pt_regs *ctx, u64 address)
{
	int stackid;

	if (!address)
		return 0;

	stackid = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
	bpf_map_update_elem(&allocs, &address, &stackid, BPF_ANY);

	/*
	 * The allocator handed this address out again, so the free recorded for
	 * it is no longer the one a later free would double up on.
	 */
	bpf_map_delete_elem(&frees, &address);

	return 0;
}

static int gen_free_enter(struct pt_regs *ctx, void *address)
{
	u64 addr = (u64)address;
	int stackid;
	struct free_info fi = {};
	struct free_info *prev;
	int *alloc_stackid;

	if (!addr)
		return 0;

	alloc_stackid = bpf_map_lookup_elem(&allocs, &addr);
	if (!alloc_stackid) {
		/*
		 * Not a live allocation: either a free was already recorded for
		 * it, which makes this a double free, or it was allocated before
		 * the probes were attached and nothing can be said about it.
		 * Only the first case needs a stack trace, and the second is the
		 * common one when attaching to a process that is already up, so
		 * the walk is left until there is something to report.
		 */
		prev = bpf_map_lookup_elem(&frees, &addr);
		if (!prev)
			return 0;

		stackid = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
		report(ctx, addr, prev->alloc_stackid, prev->free_stackid,
		       stackid);

		return 0;
	}

	fi.alloc_stackid = *alloc_stackid;
	fi.free_stackid = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);

	/*
	 * BPF_NOEXIST makes the insert the atomic claim on this free. When two
	 * threads free the same address concurrently exactly one of them wins
	 * the insert, so the loser reports instead of both concluding that they
	 * performed the legitimate free.
	 */
	if (bpf_map_update_elem(&frees, &addr, &fi, BPF_NOEXIST)) {
		prev = bpf_map_lookup_elem(&frees, &addr);
		/* No entry means the map is full, not that this is a bug. */
		if (prev)
			report(ctx, addr, prev->alloc_stackid,
			       prev->free_stackid, fi.free_stackid);

		return 0;
	}

	bpf_map_delete_elem(&allocs, &addr);

	return 0;
}

/*
 * A failed realloc() leaves the original block owned by the target, so the
 * free accounted for on entry has to be rolled back. Without this the next
 * free() of that block is reported as a double free.
 */
static int undo_free(u64 addr)
{
	struct free_info *fi = bpf_map_lookup_elem(&frees, &addr);
	int alloc_stackid;

	if (!fi)
		return 0;

	alloc_stackid = fi->alloc_stackid;
	bpf_map_update_elem(&allocs, &addr, &alloc_stackid, BPF_ANY);
	bpf_map_delete_elem(&frees, &addr);

	return 0;
}

static int gen_realloc_enter(struct pt_regs *ctx, void *ptr, u64 size)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct realloc_info ri = {};

	ri.ptr = (u64)ptr;
	ri.size = size;
	bpf_map_update_elem(&realloc_args, &pid_tgid, &ri, BPF_ANY);

	return gen_free_enter(ctx, ptr);
}

static int gen_realloc_exit(struct pt_regs *ctx, u64 address)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct realloc_info *ri = bpf_map_lookup_elem(&realloc_args, &pid_tgid);
	bool failed;
	u64 ptr;

	if (!ri)
		return gen_alloc_exit(ctx, address);

	ptr = ri->ptr;
	/*
	 * realloc() only reports failure for a non-zero size. For size zero
	 * glibc frees the block and returns NULL, which is not a failure and
	 * has to keep the free recorded on entry.
	 */
	failed = !address && ptr && ri->size;
	bpf_map_delete_elem(&realloc_args, &pid_tgid);

	if (failed)
		return undo_free(ptr);

	return gen_alloc_exit(ctx, address);
}

SEC("uretprobe")
int BPF_URETPROBE(malloc_return)
{
	return gen_alloc_exit(ctx, PT_REGS_RC(ctx));
}

SEC("uprobe")
int BPF_UPROBE(free_entry, void *address)
{
	return gen_free_enter(ctx, address);
}

SEC("uretprobe")
int BPF_URETPROBE(calloc_return)
{
	return gen_alloc_exit(ctx, PT_REGS_RC(ctx));
}

SEC("uprobe")
int BPF_UPROBE(realloc_entry, void *ptr, size_t size)
{
	return gen_realloc_enter(ctx, ptr, size);
}

SEC("uretprobe")
int BPF_URETPROBE(realloc_return)
{
	return gen_realloc_exit(ctx, PT_REGS_RC(ctx));
}

SEC("uprobe")
int BPF_UPROBE(posix_memalign_entry, void **memptr, size_t alignment, size_t size)
{
	u64 memptr64 = (u64)(size_t)memptr;
	u64 pid = bpf_get_current_pid_tgid();

	bpf_map_update_elem(&memptrs, &pid, &memptr64, BPF_ANY);

	return 0;
}

SEC("uretprobe")
int BPF_URETPROBE(posix_memalign_return)
{
	void *addr = NULL;
	u64 addr64 = 0;
	u64 pid = bpf_get_current_pid_tgid();
	u64 *memptr64 = bpf_map_lookup_elem(&memptrs, &pid);

	if (!memptr64)
		return 0;

	bpf_map_delete_elem(&memptrs, &pid);

	if (bpf_probe_read_user(&addr, sizeof(void *), (void *)(size_t)*memptr64))
		return 0;

	addr64 = (u64)(size_t)addr;

	return gen_alloc_exit(ctx, addr64);
}

SEC("uretprobe")
int BPF_URETPROBE(aligned_alloc_return)
{
	return gen_alloc_exit(ctx, PT_REGS_RC(ctx));
}

SEC("uretprobe")
int BPF_URETPROBE(valloc_return)
{
	return gen_alloc_exit(ctx, PT_REGS_RC(ctx));
}

SEC("uretprobe")
int BPF_URETPROBE(memalign_return)
{
	return gen_alloc_exit(ctx, PT_REGS_RC(ctx));
}

SEC("uretprobe")
int BPF_URETPROBE(pvalloc_return)
{
	return gen_alloc_exit(ctx, PT_REGS_RC(ctx));
}

SEC("uprobe")
int BPF_UPROBE(reallocarray_entry, void *ptr, size_t nmemb, size_t size)
{
	return gen_realloc_enter(ctx, ptr, (u64)nmemb * size);
}

SEC("uretprobe")
int BPF_URETPROBE(reallocarray_return)
{
	return gen_realloc_exit(ctx, PT_REGS_RC(ctx));
}

char _license[] SEC("license") = "Dual BSD/GPL";

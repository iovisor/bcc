// SPDX-License-Identifier: GPL-2.0
/*
 * functrace.bpf.c  Trace userspace function calls (BPF program).
 *
 * 29-Jul-2024   Eunseon Lee   Created this.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "functrace.h"

char LICENSE[] SEC("license") = "GPL";

/* Ring buffer: events flow from kernel to userspace */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);  /* 1 MiB */
} rb SEC(".maps");

/* Per-thread tracing context (shadow stack + traceId) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);                /* tid */
	__type(value, struct thread_context);
} thread_ctx SEC(".maps");

/* Root-func identification: cookie → 1 if root */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);                /* bpf_cookie (func index) */
	__type(value, __u8);               /* 1 = root-func */
} root_funcs SEC(".maps");

/* Per-thread pre-injected trace ID (userspace writes, BPF reads) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2048);
	__type(key, __u32);                /* tid */
	__type(value, __u64);              /* [0]=hi, [1]=lo packed, or two maps */
} trace_id_hi_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2048);
	__type(key, __u32);                /* tid */
	__type(value, __u64);
} trace_id_lo_map SEC(".maps");

/* Per-CPU scratch space for thread_context initialisation (avoids stack) */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct thread_context);
} empty_ctx SEC(".maps");

/* Rodata: set once from userspace before load */
const volatile __u32 target_pid     = 0;   /* 0 = trace all PIDs */
const volatile __u8  has_root_func  = 0;   /* 1 = --root-func specified */

static __always_inline __u64 gen_span_id(void)
{
	return ((__u64)bpf_get_prandom_u32() << 32) |
	       (__u64)bpf_get_prandom_u32();
}

SEC("uprobe")
int trace_func_entry(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	if (target_pid && pid != target_pid)
		return 0;

	__u64 cookie = bpf_get_attach_cookie(ctx);
	__u8 *is_root = bpf_map_lookup_elem(&root_funcs, &cookie);

	struct thread_context *tc = bpf_map_lookup_elem(&thread_ctx, &tid);
	if (!tc) {
		/* First time seeing this thread — use per-CPU scratch to init.
		 * Per-CPU array values are zero-initialised by kernel at map
		 * creation, and we reset key fields below, so no memset needed.
		 */
		__u32 zero = 0;
		struct thread_context *empty =
			bpf_map_lookup_elem(&empty_ctx, &zero);
		if (!empty)
			return 0;
		empty->recording = 0;
		empty->depth = 0;
		empty->trace_id_hi = 0;
		empty->trace_id_lo = 0;
		bpf_map_update_elem(&thread_ctx, &tid, empty, BPF_NOEXIST);
		tc = bpf_map_lookup_elem(&thread_ctx, &tid);
		if (!tc)
			return 0;
	}

	if (is_root && *is_root) {
		/* Root-func entry: start new trace */
		tc->recording = 1;
		tc->depth = 0;

		/* Read pre-injected traceId from userspace */
		__u64 *hi = bpf_map_lookup_elem(&trace_id_hi_map, &tid);
		__u64 *lo = bpf_map_lookup_elem(&trace_id_lo_map, &tid);
		tc->trace_id_hi = hi ? *hi : ((__u64)bpf_get_prandom_u32() << 32 |
					       bpf_get_prandom_u32());
		tc->trace_id_lo = lo ? *lo : ((__u64)bpf_get_prandom_u32() << 32 |
					       bpf_get_prandom_u32());
	} else if (!has_root_func) {
		/* No --root-func: Phase 1 compat — always record, but with
		 * shadow stack for parentSpanId.
		 * If depth == 0, this is effectively a "root" invocation.
		 */
		if (!tc->recording) {
			tc->recording = 1;
			tc->depth = 0;
			/* Generate random traceId inline */
			tc->trace_id_hi = ((__u64)bpf_get_prandom_u32() << 32) |
					  bpf_get_prandom_u32();
			tc->trace_id_lo = ((__u64)bpf_get_prandom_u32() << 32) |
					  bpf_get_prandom_u32();
		}
	}

	if (!tc->recording)
		return 0;

	__u8 depth = tc->depth;
	if (depth >= MAX_CALL_DEPTH)
		return 0;  /* overflow protection */

	__u64 span_id = gen_span_id();
	__u64 ts = bpf_ktime_get_ns();

	/* Push frame onto shadow stack */
	tc->stack[depth].span_id = span_id;
	tc->stack[depth].start_ns = ts;
	tc->depth = depth + 1;

	return 0;
}

SEC("uretprobe")
int trace_func_exit(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	if (target_pid && pid != target_pid)
		return 0;

	struct thread_context *tc = bpf_map_lookup_elem(&thread_ctx, &tid);
	if (!tc || !tc->recording)
		return 0;

	__u8 depth = tc->depth;
	if (depth == 0)
		return 0;  /* underflow protection — shouldn't happen */

	depth--;
	/* Bounds check for verifier */
	if (depth >= MAX_CALL_DEPTH)
		return 0;

	/* Pop frame */
	struct shadow_stack_frame *frame = &tc->stack[depth];
	__u64 end_ts = bpf_ktime_get_ns();
	__u64 cookie = bpf_get_attach_cookie(ctx);

	/* parent = next frame down in stack, or 0 for root */
	__u64 parent_span_id = 0;
	if (depth > 0 && (depth - 1) < MAX_CALL_DEPTH)
		parent_span_id = tc->stack[depth - 1].span_id;

	/* Check if this is a root-func exit */
	__u8 *is_root = bpf_map_lookup_elem(&root_funcs, &cookie);

	struct functrace_event *e =
		bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		tc->depth = depth;
		goto check_root_exit;
	}

	e->pid           = pid;
	e->tid           = tid;
	e->func_idx      = (__u32)cookie;
	e->is_root       = (is_root && *is_root) ? 1 : 0;
	e->call_depth    = depth;
	e->_pad[0]       = 0;
	e->_pad[1]       = 0;
	e->trace_id_hi   = tc->trace_id_hi;
	e->trace_id_lo   = tc->trace_id_lo;
	e->span_id       = frame->span_id;
	e->parent_span_id = parent_span_id;
	e->start_ns      = frame->start_ns;
	e->end_ns        = end_ts;

	bpf_ringbuf_submit(e, 0);
	tc->depth = depth;

check_root_exit:
	/* Root-func exit: stop recording, reset depth */
	if (is_root && *is_root) {
		tc->recording = 0;
		tc->depth = 0;
	} else if (!has_root_func && depth == 0) {
		/* No --root-func mode: top-level func returned */
		tc->recording = 0;
	}

	return 0;
}

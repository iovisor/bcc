// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 - iouringsnoop: trace io_uring submission-to-completion latency.
//
// Uses kernel tracepoints:
//   tp_btf/io_uring_submit_req  (Linux 5.17+ stable TP)
//   tp_btf/io_uring_complete    (Linux 5.10+ stable TP)
//
// Falls back to raw_tp variants on kernels without BTF-typed tracepoints.
//
// Request state is keyed by the io_kiocb pointer which is unique per
// in-flight request.  On completion the entry is deleted to prevent
// map-state leaks.
//
// Event transport: BPF_MAP_TYPE_PERF_EVENT_ARRAY (compatible with older
// kernels; ring-buffer can be layered on top in userspace if needed).

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "iouringsnoop.h"

#define MAX_ENTRIES	102400

/* ---------- configurable constants (set from userspace via rodata) --------- */

/* Filter by submitting PID; 0 = trace all */
const volatile pid_t targ_pid = 0;

/* Filter by process name prefix; empty = trace all */
const volatile char targ_comm[TASK_COMM_LEN] = {};
const volatile bool filter_comm = false;

/* Minimum latency threshold in microseconds; 0 = no threshold */
const volatile __u64 min_us = 0;

/* Filter by io_ring_ctx pointer; 0 = trace all rings */
const volatile __u64 targ_ctx = 0;

/* When true, report only requests where res < 0 */
const volatile bool errors_only = false;

/* ---------- internal state ------------------------------------------------- */

/*
 * submit_map: io_kiocb* → submission timestamp (ns)
 *
 * The io_kiocb pointer is unique for each in-flight request and is visible
 * in both the submit and complete tracepoints, making it the natural key.
 * We cast it to u64 to satisfy BPF map key constraints.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key,   u64);   /* io_kiocb* cast to u64 */
	__type(value, u64);   /* bpf_ktime_get_ns() at submit */
} submit_map SEC(".maps");

/*
 * pid_map: io_kiocb* → piddata
 *
 * We capture PID + comm at submit time (the task context is the submitter).
 * At complete time the task context may differ (kworker / io_uring-sq thread).
 */
struct piddata {
	u32  pid;
	char comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key,   u64);           /* io_kiocb* cast to u64 */
	__type(value, struct piddata);
} pid_map SEC(".maps");

/* ---------- output --------------------------------------------------------- */

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size,   sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

/* ---------- helpers -------------------------------------------------------- */

static __always_inline bool comm_allowed(const char *comm)
{
	int i;

	for (i = 0; i < TASK_COMM_LEN && targ_comm[i] != '\0'; i++) {
		if (comm[i] != targ_comm[i])
			return false;
	}
	return true;
}

/*
 * handle_submit - record submission timestamp + task metadata.
 *
 * Called from both tp_btf and raw_tp variants of io_uring_submit_req.
 * @req_ptr: io_kiocb pointer (cast to u64 for map key).
 * @opcode:  IORING_OP_* opcode at submit time.
 * @ctx_ptr: io_ring_ctx pointer (cast to u64 for optional ring filter).
 */
static __always_inline int
handle_submit(u64 req_ptr, u8 opcode, u64 ctx_ptr)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
	struct piddata pd = {};
	u64 ts;

	/* PID filter */
	if (targ_pid && targ_pid != pid)
		return 0;

	/* Ring filter */
	if (targ_ctx && targ_ctx != ctx_ptr)
		return 0;

	/* Comm filter */
	if (filter_comm) {
		bpf_get_current_comm(pd.comm, sizeof(pd.comm));
		if (!comm_allowed(pd.comm))
			return 0;
	} else {
		bpf_get_current_comm(pd.comm, sizeof(pd.comm));
	}

	pd.pid = pid;

	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&submit_map, &req_ptr, &ts,      BPF_ANY);
	bpf_map_update_elem(&pid_map,    &req_ptr, &pd,      BPF_ANY);
	return 0;
}

/*
 * handle_complete - compute latency and emit event.
 *
 * Called from both tp_btf and raw_tp variants of io_uring_complete.
 * @ctx:     BPF context pointer (for bpf_perf_event_output).
 * @req_ptr: io_kiocb pointer (cast to u64, must match submit_map key).
 * @ctx_ptr: io_ring_ctx pointer for the ring field in the event.
 * @res:     CQE result value.
 * @opcode:  IORING_OP_* — if available from the tracepoint arguments.
 *           Pass 0xFF when the complete TP does not carry opcode; we will
 *           look it up from the io_kiocb if possible.
 */
static __always_inline int
handle_complete(void *bpf_ctx, u64 req_ptr, u64 ctx_ptr, s32 res, u8 opcode)
{
	u64 *tsp;
	struct piddata *pdp;
	struct event ev = {};
	u64 now, delta_ns;
	s64 delta_s64;

	tsp = bpf_map_lookup_elem(&submit_map, &req_ptr);
	if (!tsp)
		return 0; /* no submit recorded – missed or filtered */

	now = bpf_ktime_get_ns();
	delta_s64 = (s64)(now - *tsp);
	if (delta_s64 < 0)
		goto cleanup; /* clock skew / wrap – discard */

	delta_ns = (u64)delta_s64;

	/* Minimum latency filter */
	if (min_us && (delta_ns / 1000) < min_us)
		goto cleanup;

	/* Error-only filter */
	if (errors_only && res >= 0)
		goto cleanup;

	pdp = bpf_map_lookup_elem(&pid_map, &req_ptr);
	if (pdp) {
		ev.pid = pdp->pid;
		__builtin_memcpy(ev.comm, pdp->comm, sizeof(ev.comm));
	} else {
		ev.comm[0] = '?';
	}

	ev.delta_us = delta_ns / 1000;
	ev.ctx      = ctx_ptr;
	ev.req      = req_ptr;
	ev.res      = res;
	ev.opcode   = opcode;

	bpf_perf_event_output(bpf_ctx, &events, BPF_F_CURRENT_CPU,
			      &ev, sizeof(ev));

cleanup:
	bpf_map_delete_elem(&submit_map, &req_ptr);
	bpf_map_delete_elem(&pid_map,    &req_ptr);
	return 0;
}

/* ==========================================================================
 * BTF-typed tracepoints (preferred; Linux 5.17+ for submit_req,
 *                                          Linux 5.10+ for complete)
 *
 * Kernel tracepoint signatures (from include/trace/events/io_uring.h):
 *
 *  TRACE_EVENT(io_uring_submit_req,
 *      TP_PROTO(struct io_kiocb *req),          <- single arg
 *      ...
 *  )
 *
 *  TRACE_EVENT(io_uring_complete,
 *      TP_PROTO(struct io_ring_ctx *ctx, void *req, struct io_uring_cqe *cqe),
 *      ...
 *  )
 * ========================================================================== */

SEC("tp_btf/io_uring_submit_req")
int BPF_PROG(io_uring_submit_req_btf, struct io_kiocb *req)
{
	u64 req_ptr = (u64)(unsigned long)req;
	u64 ctx_ptr = (u64)(unsigned long)BPF_CORE_READ(req, ctx);
	u8  opcode  = BPF_CORE_READ(req, opcode);

	return handle_submit(req_ptr, opcode, ctx_ptr);
}

SEC("tp_btf/io_uring_complete")
int BPF_PROG(io_uring_complete_btf, struct io_ring_ctx *ring_ctx,
	     void *req, struct io_uring_cqe *cqe)
{
	u64 req_ptr = (u64)(unsigned long)req;
	u64 ctx_ptr = (u64)(unsigned long)ring_ctx;
	s32 res     = BPF_CORE_READ(cqe, res);
	u8  opcode  = 0;

	/*
	 * The complete tracepoint does not carry the opcode directly.
	 * We read it from the io_kiocb via CO-RE.  This is safe because
	 * the io_kiocb is still alive at complete time — the kernel frees
	 * it only after the tracepoint fires.
	 */
	if (req) {
		struct io_kiocb *kiocb = (struct io_kiocb *)req;

		opcode = BPF_CORE_READ(kiocb, opcode);
	}

	return handle_complete(ctx, req_ptr, ctx_ptr, res, opcode);
}

/* ==========================================================================
 * Raw tracepoint fallback (Linux 5.10 – 5.16 where tp_btf may not carry
 * full type info for these specific tracepoints).
 *
 * raw_tp args are the same as TP_PROTO but without type decorators;
 * they are accessed via ctx[0], ctx[1], ...
 *
 *  io_uring_submit_req:  ctx[0] = struct io_kiocb *
 *  io_uring_complete:    ctx[0] = struct io_ring_ctx *
 *                        ctx[1] = void *req (io_kiocb *)
 *                        ctx[2] = struct io_uring_cqe *
 * ========================================================================== */

SEC("raw_tp/io_uring_submit_req")
int BPF_PROG(io_uring_submit_req_raw)
{
	struct io_kiocb *req = (struct io_kiocb *)ctx[0];
	u64 req_ptr = (u64)(unsigned long)req;
	u64 ctx_ptr = (u64)(unsigned long)BPF_CORE_READ(req, ctx);
	u8  opcode  = BPF_CORE_READ(req, opcode);

	return handle_submit(req_ptr, opcode, ctx_ptr);
}

SEC("raw_tp/io_uring_complete")
int BPF_PROG(io_uring_complete_raw)
{
	struct io_ring_ctx  *ring = (struct io_ring_ctx *)ctx[0];
	void                *req  = (void *)ctx[1];
	struct io_uring_cqe *cqe  = (struct io_uring_cqe *)ctx[2];

	u64 req_ptr = (u64)(unsigned long)req;
	u64 ctx_ptr = (u64)(unsigned long)ring;
	s32 res     = BPF_CORE_READ(cqe, res);
	u8  opcode  = 0;

	if (req) {
		struct io_kiocb *kiocb = (struct io_kiocb *)req;
		opcode = BPF_CORE_READ(kiocb, opcode);
	}

	return handle_complete(ctx, req_ptr, ctx_ptr, res, opcode);
}

char LICENSE[] SEC("license") = "GPL";

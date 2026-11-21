/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __FUNCTRACE_H
#define __FUNCTRACE_H

#define TASK_COMM_LEN 16
#define FUNC_NAME_LEN 64
#define MAX_CALL_DEPTH 64

/**
 * struct shadow_stack_frame - Single frame in per-thread shadow stack.
 *
 * Stored in BPF map (thread_ctx).  Pushed on uprobe entry,
 * popped on uretprobe exit.
 */
struct shadow_stack_frame {
	__u64 span_id;      /* span ID assigned to this function invocation */
	__u64 start_ns;     /* bpf_ktime_get_ns() at function entry */
};

/**
 * struct thread_context - Per-thread tracing context (BPF map value).
 *
 * Holds the shadow stack and current trace ID for one TID.
 * Total size: 8 + 8 + 8 + 8 + 64*16 = 1056 bytes (fits in BPF map value).
 */
struct thread_context {
	__u8  recording;                              /* 1 = actively tracing */
	__u8  depth;                                  /* current shadow stack depth */
	__u8  _pad[6];
	__u64 trace_id_hi;                            /* 128bit traceId upper */
	__u64 trace_id_lo;                            /* 128bit traceId lower */
	struct shadow_stack_frame stack[MAX_CALL_DEPTH];
};

/**
 * struct functrace_event - ring-buffer record from the BPF program.
 *
 * Sent on every uretprobe firing.  All timestamp fields are
 * CLOCK_MONOTONIC nanoseconds (bpf_ktime_get_ns()).  Userspace
 * converts them to CLOCK_REALTIME via convert_to_realtime_ns().
 */
struct functrace_event {
	__u32 pid;
	__u32 tid;
	__u32 func_idx;       /* index into userspace env.functions[] */
	__u8  is_root;        /* 1 = root-func span */
	__u8  call_depth;     /* depth in shadow stack (0-based) */
	__u8  _pad[2];
	__u64 trace_id_hi;    /* 128bit traceId upper */
	__u64 trace_id_lo;    /* 128bit traceId lower */
	__u64 span_id;
	__u64 parent_span_id;
	__u64 start_ns;
	__u64 end_ns;
};

#endif /* __FUNCTRACE_H */

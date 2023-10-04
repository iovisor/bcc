/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021, Oracle and/or its affiliates. */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "ksnoop.h"

/* For kretprobes, the instruction pointer in the struct pt_regs context
 * is the kretprobe_trampoline.  We derive the instruction pointer
 * by pushing it onto a function stack on entry and popping it on return.
 *
 * We could use bpf_get_func_ip(), but "stack mode" - where we
 * specify functions "a", "b and "c" and only want to see a trace if "a"
 * calls "b" and "b" calls "c" - utilizes this stack to determine if trace
 * data should be collected.
 */
#define FUNC_MAX_STACK_DEPTH	16
/* used to convince verifier we do not stray outside of array bounds */
#define FUNC_STACK_DEPTH_MASK	(FUNC_MAX_STACK_DEPTH - 1)

#ifndef ENOSPC
#define ENOSPC			28
#endif

struct func_stack {
	__u64 task;
	__u64 ips[FUNC_MAX_STACK_DEPTH];
	__u8 stack_depth;
};

#define MAX_TASKS		2048

/* function call stack hashed on a per-task key */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	/* function call stack for functions we are tracing */
	__uint(max_entries, MAX_TASKS);
	__type(key, __u64);
	__type(value, struct func_stack);
} ksnoop_func_stack SEC(".maps");

/* per-cpu trace info hashed on function address */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, MAX_FUNC_TRACES);
	__type(key, __u64);
	__type(value, struct trace);
} ksnoop_func_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(value_size, sizeof(int));
	__uint(key_size, sizeof(int));
} ksnoop_perf_map SEC(".maps");

static void clear_trace(struct trace *trace)
{
	__builtin_memset(&trace->trace_data, 0, sizeof(trace->trace_data));
	trace->data_flags = 0;
	trace->buf_len = 0;
}

static struct trace *get_trace(struct pt_regs *ctx, bool entry)
{
	__u8 stack_depth, last_stack_depth;
	struct func_stack *func_stack;
	__u64 ip, last_ip = 0, task;
	struct trace *trace;

	task = bpf_get_current_task();

	func_stack = bpf_map_lookup_elem(&ksnoop_func_stack, &task);
	if (!func_stack) {
		struct func_stack new_stack = { .task = task };

		bpf_map_update_elem(&ksnoop_func_stack, &task, &new_stack,
				    BPF_NOEXIST);
		func_stack = bpf_map_lookup_elem(&ksnoop_func_stack, &task);
		if (!func_stack)
			return NULL;
	}

	stack_depth = func_stack->stack_depth;
	if (stack_depth > FUNC_MAX_STACK_DEPTH)
		return NULL;

	if (entry) {
		if (bpf_core_enum_value_exists(enum bpf_func_id,
					       BPF_FUNC_get_func_ip))
			ip = bpf_get_func_ip(ctx);
		else
			ip = KSNOOP_IP_FIX(PT_REGS_IP_CORE(ctx));
		if (stack_depth >= FUNC_MAX_STACK_DEPTH - 1)
			return NULL;
		/* verifier doesn't like using "stack_depth - 1" as array index
		 * directly.
		 */
		last_stack_depth = stack_depth - 1;
		/* get address of last function we called */
		if (last_stack_depth >= 0 &&
		    last_stack_depth < FUNC_MAX_STACK_DEPTH)
			last_ip = func_stack->ips[last_stack_depth];
		/* push ip onto stack. return will pop it. */
		func_stack->ips[stack_depth] = ip;
		/* mask used in case bounds checks are optimized out */
		stack_depth = (stack_depth + 1) & FUNC_STACK_DEPTH_MASK;
		func_stack->stack_depth = stack_depth;
		/* rather than zero stack entries on popping, we zero the
		 * (stack_depth + 1)'th entry when pushing the current
		 * entry.  The reason we take this approach is that
		 * when tracking the set of functions we returned from,
		 * we want the history of functions we returned from to
		 * be preserved.
		 */
		if (stack_depth < FUNC_MAX_STACK_DEPTH)
			func_stack->ips[stack_depth] = 0;
	} else {
		if (stack_depth == 0 || stack_depth >= FUNC_MAX_STACK_DEPTH)
			return NULL;
		last_stack_depth = stack_depth;
		/* get address of last function we returned from */
		if (last_stack_depth >= 0 &&
		    last_stack_depth < FUNC_MAX_STACK_DEPTH)
			last_ip = func_stack->ips[last_stack_depth];
		if (stack_depth > 0) {
			/* logical OR convinces verifier that we don't
			 * end up with a < 0 value, translating to 0xff
			 * and an outside of map element access.
			 */
			stack_depth = (stack_depth - 1) & FUNC_STACK_DEPTH_MASK;
		}
		/* retrieve ip from stack as IP in pt_regs is
		 * bpf kretprobe trampoline address.
		 */
		if (stack_depth >= 0 && stack_depth < FUNC_MAX_STACK_DEPTH)
			ip = func_stack->ips[stack_depth];
		if (stack_depth >= 0 && stack_depth < FUNC_MAX_STACK_DEPTH)
			func_stack->stack_depth = stack_depth;
	}

	trace = bpf_map_lookup_elem(&ksnoop_func_map, &ip);
	if (!trace)
		return NULL;

	/* we may stash data on entry since predicates are a mix
	 * of entry/return; in such cases, trace->flags specifies
	 * KSNOOP_F_STASH, and we will output stashed data on return.
	 * If returning, make sure we don't clear our stashed data.
	 */
	if (!entry && (trace->flags & KSNOOP_F_STASH)) {
		/* skip clearing trace data */
		if (!(trace->data_flags & KSNOOP_F_STASHED)) {
			/* predicate must have failed */
			return NULL;
		}
		/* skip clearing trace data */
	} else {
		/* clear trace data before starting. */
		clear_trace(trace);
	}

	if (entry) {
		/* if in stack mode, check if previous fn matches */
		if (trace->prev_ip && trace->prev_ip != last_ip)
			return NULL;
		/* if tracing intermediate fn in stack of fns, stash data. */
		if (trace->next_ip)
			trace->data_flags |= KSNOOP_F_STASH;
		/* we may stash data on entry since predicates are a mix
		 * of entry/return; in such cases, trace->flags specifies
		 * KSNOOP_F_STASH, and we will output stashed data on return.
		 */
		if (trace->flags & KSNOOP_F_STASH)
			trace->data_flags |= KSNOOP_F_STASH;
		/* otherwise the data is outputted (because we've reached
		 * the last fn in the set of fns specified).
		 */
	} else {
		/* In stack mode, check if next fn matches the last fn
		 * we returned from; i.e. "a" called "b", and now
		 * we're at "a", was the last fn we returned from "b"?
		 * If so, stash data for later display (when we reach the
		 * first fn in the set of stack fns).
		 */
		if (trace->next_ip && trace->next_ip != last_ip)
			return NULL;
		if (trace->prev_ip)
			trace->data_flags |= KSNOOP_F_STASH;
		/* If there is no "prev" function, i.e. we are at the
		 * first function in a set of stack functions, the trace
		 * info is shown (along with any stashed info associated
		 * with callers).
		 */
	}
	trace->task = task;
	return trace;
}

static void output_trace(struct pt_regs *ctx, struct trace *trace)
{
	__u16 trace_len;

	if (trace->buf_len == 0)
		goto skip;

	/* we may be simply stashing values, and will report later */
	if (trace->data_flags & KSNOOP_F_STASH) {
		trace->data_flags &= ~KSNOOP_F_STASH;
		trace->data_flags |= KSNOOP_F_STASHED;
		return;
	}
	/* we may be outputting earlier stashed data */
	if (trace->data_flags & KSNOOP_F_STASHED)
		trace->data_flags &= ~KSNOOP_F_STASHED;

	/* trim perf event size to only contain data we've recorded. */
	trace_len = sizeof(*trace) + trace->buf_len - MAX_TRACE_BUF;

	if (trace_len <= sizeof(*trace))
		bpf_perf_event_output(ctx, &ksnoop_perf_map,
				      BPF_F_CURRENT_CPU,
				      trace, trace_len);
skip:
	clear_trace(trace);
}

static void output_stashed_traces(struct pt_regs *ctx,
					 struct trace *currtrace,
					 bool entry)
{
	struct func_stack *func_stack;
	struct trace *trace = NULL;
	__u8 i;
	__u64 task = 0;

	task = bpf_get_current_task();
	func_stack = bpf_map_lookup_elem(&ksnoop_func_stack, &task);
	if (!func_stack)
		return;

	if (entry) {
		/* iterate from bottom to top of stack, outputting stashed
		 * data we find.  This corresponds to the set of functions
		 * we called before the current function.
		 */
		for (i = 0;
		     i < func_stack->stack_depth - 1 && i < FUNC_MAX_STACK_DEPTH;
		     i++) {
			trace = bpf_map_lookup_elem(&ksnoop_func_map,
						    &func_stack->ips[i]);
			if (!trace || !(trace->data_flags & KSNOOP_F_STASHED))
				break;
			if (trace->task != task)
				return;
			output_trace(ctx, trace);
		}
	} else {
		/* iterate from top to bottom of stack, outputting stashed
		 * data we find.  This corresponds to the set of functions
		 * that returned prior to the current returning function.
		 */
		for (i = FUNC_MAX_STACK_DEPTH; i > 0; i--) {
			__u64 ip;

			ip = func_stack->ips[i];
			if (!ip)
				continue;
			trace = bpf_map_lookup_elem(&ksnoop_func_map, &ip);
			if (!trace || !(trace->data_flags & KSNOOP_F_STASHED))
				break;
			if (trace->task != task)
				return;
			output_trace(ctx, trace);
		}
	}
	/* finally output the current trace info */
	output_trace(ctx, currtrace);
}

static __u64 get_arg(struct pt_regs *ctx, enum arg argnum)
{
	switch (argnum) {
	case KSNOOP_ARG1:
		return PT_REGS_PARM1_CORE(ctx);
	case KSNOOP_ARG2:
		return PT_REGS_PARM2_CORE(ctx);
	case KSNOOP_ARG3:
		return PT_REGS_PARM3_CORE(ctx);
	case KSNOOP_ARG4:
		return PT_REGS_PARM4_CORE(ctx);
	case KSNOOP_ARG5:
		return PT_REGS_PARM5_CORE(ctx);
	case KSNOOP_RETURN:
		return PT_REGS_RC_CORE(ctx);
	default:
		return 0;
	}
}

static int ksnoop(struct pt_regs *ctx, bool entry)
{
	void *data_ptr = NULL;
	struct trace *trace;
	__u64 data;
	__u32 currpid;
	int ret;
	__u8 i;

	trace = get_trace(ctx, entry);
	if (!trace)
		return 0;

	/* make sure we want events from this pid */
	currpid = bpf_get_current_pid_tgid();
	if (trace->filter_pid && trace->filter_pid != currpid)
		return 0;
	trace->pid = currpid;

	trace->cpu = bpf_get_smp_processor_id();
	trace->time = bpf_ktime_get_ns();

	trace->data_flags &= ~(KSNOOP_F_ENTRY | KSNOOP_F_RETURN);
	if (entry)
		trace->data_flags |= KSNOOP_F_ENTRY;
	else
		trace->data_flags |= KSNOOP_F_RETURN;


	for (i = 0; i < MAX_TRACES; i++) {
		struct trace_data *currdata;
		struct value *currtrace;
		char *buf_offset = NULL;
		__u32 tracesize;

		currdata = &trace->trace_data[i];
		currtrace = &trace->traces[i];

		if ((entry && !base_arg_is_entry(currtrace->base_arg)) ||
		    (!entry && base_arg_is_entry(currtrace->base_arg)))
			continue;

		/* skip void (unused) trace arguments, ensuring not to
		 * skip "void *".
		 */
		if (currtrace->type_id == 0 &&
		    !(currtrace->flags & KSNOOP_F_PTR))
			continue;

		data = get_arg(ctx, currtrace->base_arg);

		/* look up member value and read into data field. */
		if (currtrace->flags & KSNOOP_F_MEMBER) {
			if (currtrace->offset)
				data += currtrace->offset;

			/* member is a pointer; read it in */
			if (currtrace->flags & KSNOOP_F_PTR) {
				void *dataptr = (void *)data;

				ret = bpf_probe_read_kernel(&data, sizeof(data), dataptr);
				if (ret) {
					currdata->err_type_id = currtrace->type_id;
					currdata->err = ret;
					continue;
				}
				currdata->raw_value = data;
			} else if (currtrace->size <=
				   sizeof(currdata->raw_value)) {
				/* read member value for predicate comparison */
				bpf_probe_read_kernel(&currdata->raw_value, currtrace->size, (void*)data);
			}
		} else {
			currdata->raw_value = data;
		}

		/* simple predicate evaluation: if any predicate fails,
		 * skip all tracing for this function.
		 */
		if (currtrace->flags & KSNOOP_F_PREDICATE_MASK) {
			bool ok = false;

			if (currtrace->flags & KSNOOP_F_PREDICATE_EQ &&
			    currdata->raw_value == currtrace->predicate_value)
				ok = true;

			if (currtrace->flags & KSNOOP_F_PREDICATE_NOTEQ &&
			    currdata->raw_value != currtrace->predicate_value)
				ok = true;

			if (currtrace->flags & KSNOOP_F_PREDICATE_GT &&
			    currdata->raw_value > currtrace->predicate_value)
				ok = true;

			if (currtrace->flags & KSNOOP_F_PREDICATE_LT &&
			    currdata->raw_value < currtrace->predicate_value)
				ok = true;

			if (!ok) {
				clear_trace(trace);
				return 0;
			}
		}

		if (currtrace->flags & (KSNOOP_F_PTR | KSNOOP_F_MEMBER))
			data_ptr = (void *)data;
		else
			data_ptr = &data;

		if (trace->buf_len + MAX_TRACE_DATA >= MAX_TRACE_BUF)
			break;

		buf_offset = &trace->buf[trace->buf_len];
		if (buf_offset > &trace->buf[MAX_TRACE_BUF]) {
			currdata->err_type_id = currtrace->type_id;
			currdata->err = -ENOSPC;
			continue;
		}
		currdata->buf_offset = trace->buf_len;

		tracesize = currtrace->size;
		if (tracesize > MAX_TRACE_DATA)
			tracesize = MAX_TRACE_DATA;
		ret = bpf_probe_read_kernel(buf_offset, tracesize, data_ptr);
		if (ret < 0) {
			currdata->err_type_id = currtrace->type_id;
			currdata->err = ret;
			continue;
		} else {
			currdata->buf_len = tracesize;
			trace->buf_len += tracesize;
		}
	}

	/* show accumulated stashed traces (if any) */
	if ((entry && trace->prev_ip && !trace->next_ip) ||
	    (!entry && trace->next_ip && !trace->prev_ip))
		output_stashed_traces(ctx, trace, entry);
	else
		output_trace(ctx, trace);

	return 0;
}

SEC("kprobe/foo")
int BPF_KPROBE(kprobe_entry)
{
	return ksnoop(ctx, true);
}

SEC("kretprobe/foo")
int BPF_KRETPROBE(kprobe_return)
{
	return ksnoop(ctx, false);
}

char _license[] SEC("license") = "Dual BSD/GPL";

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __UNWIND_BPF_H
#define __UNWIND_BPF_H

#include "unwind_types.h"
#include "maps.bpf.h"

/*
 * Post mortem Dwarf CFI based unwinding on top of regs and stack dumps.
 *
 * Lots of this code have been borrowed or heavily inspired from parts of
 * the libunwind and perf codes.
 */

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define DEFAULT_MAX_ENTRIES 1024
#define DEFAULT_USTACK_SIZE 256

const volatile bool sample_user_stack = false;
const volatile unsigned long sample_ustack_size = DEFAULT_USTACK_SIZE;
const volatile int sample_max_entries = DEFAULT_MAX_ENTRIES;

/*
 * map to store sample data
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct sample_data);
} SAMPLES_MAP SEC(".maps");

/*
 * map to store user stack
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
} USTACKS_MAP SEC(".maps");

/*
 * get_user_stackid - get user stack and user regs id for @ctx
 *
 * This function returns id of dumped user stack and registers for the context
 */
static int get_user_stackid()
{
	struct sample_data *sample;
	struct task_struct *task;
	struct mm_struct *mm;
	struct pt_regs *ctx;
	static const struct sample_data szero;
	static const char zero[MAX_USTACK_SIZE] = {0, };
	__u64* ustack;
	static __u32 id = 0;
	u64 sp;
	u32 stack_len;
	u32 dump_len;

	task = bpf_get_current_task_btf();
	ctx = (struct pt_regs *)bpf_task_pt_regs(task);

	mm = BPF_CORE_READ(task, mm);
	if (!mm)
		return -1;

	if (id >= sample_max_entries)
		return -1;

	__sync_fetch_and_add(&id, 1);

	sample = bpf_map_lookup_or_try_init(&samples, &id, &szero);
	if (!sample)
		return -1;

	ustack = bpf_map_lookup_or_try_init(&ustacks, &id, &zero);
	if (!ustack)
		return -1;

	/* dump user regs */
	bpf_probe_read(&sample->user_regs, sizeof(struct pt_regs), ctx);

	/* dump user stack */
	sp = PT_REGS_SP_CORE(ctx);
	stack_len = BPF_CORE_READ(mm, start_stack) - sp;
	dump_len = MIN(stack_len, sample_ustack_size);

	if (bpf_probe_read_user(ustack, dump_len, (void*)sp) == 0)
		sample->user_stack.size = dump_len;

	return id;
}

#endif /* __UNWIND_BPF_H */

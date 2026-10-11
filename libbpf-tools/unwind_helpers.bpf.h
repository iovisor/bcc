// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright 2023 LG Electronics Inc.
#ifndef __UNWIND_HELPERS_BPF_H
#define __UNWIND_HELPERS_BPF_H

#include <asm-generic/errno.h>
#include "unwind_helpers_types.h"
#include "maps.bpf.h"

/*
 * The usage is documented in unwind_helpers.h
 *
 * This file internally creates two maps to store user registers and user stack.
 */

#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define DEFAULT_MAX_ENTRIES 1
#define DEFAULT_USTACK_SIZE 256

const volatile bool dwarf_unwind = false;
const volatile int targ_sample_max_entries = DEFAULT_MAX_ENTRIES;
const volatile unsigned long targ_ustack_size = DEFAULT_USTACK_SIZE;

/*
 * Map to store sample data
 * The length of the dumped stack and the regs dump are saved.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct sample_data);
	__uint(max_entries, 1);
} UW_SAMPLES_MAP SEC(".maps");

/*
 * Map to store stack dumps
 * Separated map to allow value sizes to be adjusted at load time.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} UW_STACKS_MAP SEC(".maps");

/*
 * Returns the ID of the user sample dumped for the current context.
 */
static int uw_get_stackid()
{
	struct sample_data *sample;
	struct task_struct *task;
	struct mm_struct *mm;
	struct pt_regs *ctx;
	static const struct sample_data szero = {0, };
	static const char uzero[UW_STACK_MAX_SZ] = {0, };
	__u64* ustack;
	static __u32 id = 0;
	u64 sp;
	u32 stack_len;
	u32 dump_len;

	task = bpf_get_current_task_btf();
	ctx = (struct pt_regs *)bpf_task_pt_regs(task);

	mm = BPF_CORE_READ(task, mm);
	if (!mm)
		return -EINVAL;

	if (id >= targ_sample_max_entries)
		return -ENOMEM;

	__sync_fetch_and_add(&id, 1);

	sample = bpf_map_lookup_or_try_init(&UW_SAMPLES_MAP, &id, &szero);
	if (!sample)
		return -ENOENT;

	ustack = bpf_map_lookup_or_try_init(&UW_STACKS_MAP, &id, &uzero);
	if (!ustack)
		return -ENOENT;

	/* dump user regs */
	bpf_probe_read(&sample->user_regs, sizeof(struct pt_regs), ctx);

	/* dump user stack */
	sp = PT_REGS_SP_CORE(ctx);
	stack_len = BPF_CORE_READ(mm, start_stack) - sp;
	dump_len = MIN(stack_len, targ_ustack_size);

	if (bpf_probe_read_user(ustack, dump_len, (void*)sp) == 0)
		sample->user_stack.size = dump_len;

	return id;
}

#endif /* __UNWIND_HELPERS_BPF_H */

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Hengqi Chen */

#ifndef __CORE_FIXES_BPF_H
#define __CORE_FIXES_BPF_H

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>

/**
 * commit 2f064a59a1 ("sched: Change task_struct::state") changes
 * the name of task_struct::state to task_struct::__state
 * see:
 *     https://github.com/torvalds/linux/commit/2f064a59a1
 */
struct task_struct___x {
	unsigned int __state;
} __attribute__((preserve_access_index));

/**
 * commit 309dca309fc3 ("block: store a block_device pointer in struct bio")
 * adds a new member bi_bdev which is a pointer to struct block_device
 * see:
 *     https://github.com/torvalds/linux/commit/309dca309fc3
 */
struct bio___x {
	struct block_device *bi_bdev;
} __attribute__((preserve_access_index));

static __always_inline __s64 get_task_state(void *task)
{
	struct task_struct___x *t = task;

	if (bpf_core_field_exists(t->__state))
		return BPF_CORE_READ(t, __state);
	return BPF_CORE_READ((struct task_struct *)task, state);
}

static __always_inline struct gendisk *get_gendisk(void *bio)
{
	struct bio___x *b = bio;

	if (bpf_core_field_exists(b->bi_bdev))
		return BPF_CORE_READ(b, bi_bdev, bd_disk);
	return BPF_CORE_READ((struct bio *)bio, bi_disk);
}

#endif /* __CORE_FIXES_BPF_H */

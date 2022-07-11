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
struct task_struct___new {
	unsigned int __state;
} __attribute__((preserve_access_index));

struct task_struct___old {
	volatile long state;
} __attribute__((preserve_access_index));

static __always_inline __s64 get_task_state(void *task)
{
	struct task_struct___new *t = task;
	struct task_struct___old *o = task;

	if (bpf_core_field_exists(t->__state))
		return BPF_CORE_READ(t, __state);
	else if (bpf_core_field_exists(o->state))
		return BPF_CORE_READ(o, state);
	return 0;
}

/**
 * commit 309dca309fc3 ("block: store a block_device pointer in struct bio")
 * adds a new member bi_bdev which is a pointer to struct block_device
 * see:
 *     https://github.com/torvalds/linux/commit/309dca309fc3
 */
struct bio___new {
	struct block_device *bi_bdev;
} __attribute__((preserve_access_index));

struct bio___old {
	struct gendisk *bi_disk;
} __attribute__((preserve_access_index));

static __always_inline struct gendisk *get_gendisk(void *bio)
{
	struct bio___new *b = bio;
	struct bio___old *c = bio;

	if (bpf_core_field_exists(b->bi_bdev))
		return BPF_CORE_READ(b, bi_bdev, bd_disk);
	else if (bpf_core_field_exists(c->bi_disk))
		return BPF_CORE_READ(c, bi_disk);
	return NULL;
}

/**
 * commit d5869fdc189f ("block: introduce block_rq_error tracepoint")
 * adds a new tracepoint block_rq_error and it shares the same arguments
 * with tracepoint block_rq_complete. As a result, the kernel BTF now has
 * a `struct trace_event_raw_block_rq_completion` instead of
 * `struct trace_event_raw_block_rq_complete`.
 * see:
 *     https://github.com/torvalds/linux/commit/d5869fdc189f
 */
struct trace_event_raw_block_rq_completion___x {
	dev_t dev;
	sector_t sector;
	unsigned int nr_sector;
} __attribute__((preserve_access_index));

static __always_inline bool has_block_rq_completion()
{
	if (bpf_core_type_exists(struct trace_event_raw_block_rq_completion___x))
		return true;
	return false;
}

#endif /* __CORE_FIXES_BPF_H */

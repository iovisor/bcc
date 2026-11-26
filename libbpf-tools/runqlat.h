/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __RUNQLAT_H
#define __RUNQLAT_H

#define TASK_COMM_LEN	16
#define MAX_SLOTS	26

/* with --split, set in a per-pid/tid hist key when the wait followed a preemption */
#define RUNQLAT_PREEMPT_BIT	(1U << 31)

struct hist {
	__u32 slots[MAX_SLOTS];
	char comm[TASK_COMM_LEN];
};

#endif /* __RUNQLAT_H */

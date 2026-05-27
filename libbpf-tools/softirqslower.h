/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __SOFTIRQSLOWER_H
#define __SOFTIRQSLOWER_H

#define TASK_COMM_LEN	16
/* Matches NR_SOFTIRQS in linux/interrupt.h
 * Update if kernel adds new vectors */
#define NR_SOFTIRQS	10

enum softirq_stage {
	STAGE_RAISE_TO_ENTRY = 0, /* raise_softirq -> softirq handler entry */
	STAGE_ENTRY_TO_EXIT  = 1, /* softirq handler entry -> exit (runtime) */
};

struct event {
	__u64 delta_us;
	__u32 stage;
	__u32 vec;
	__u32 cpu;
	char  task[TASK_COMM_LEN];
};

#endif /* __SOFTIRQSLOWER_H */

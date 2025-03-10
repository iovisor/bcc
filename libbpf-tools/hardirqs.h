/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __HARDIRQS_H
#define __HARDIRQS_H

#define MAX_SLOTS	20

struct irq_key {
	char name[32];
	__u32 cpu;
};

struct info {
	__u64 count;
	__u64 total_time;
	__u64 max_time;
	__u32 slots[MAX_SLOTS];
};

#endif /* __HARDIRQS_H */

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __HARDIRQS_H
#define __HARDIRQS_H

#define MAX_SLOTS	20

struct irq_key {
	char name[32];
};

struct info {
	__u64 count;
	__u32 slots[MAX_SLOTS];
};

#endif /* __HARDIRQS_H */

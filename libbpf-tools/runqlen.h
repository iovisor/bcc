/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __RUNQLEN_H
#define __RUNQLEN_H

#define MAX_CPU_NR	128
#define MAX_SLOTS	32

struct hist {
	__u32 slots[MAX_SLOTS];
};

#endif /* __RUNQLEN_H */

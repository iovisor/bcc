/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __SOFTIRQS_H
#define __SOFTIRQS_H

#define MAX_SLOTS	20

struct hist {
	__u32 slots[MAX_SLOTS];
};

#endif /* __SOFTIRQS_H */

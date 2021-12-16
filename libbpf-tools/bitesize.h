// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __BITESIZE_H
#define __BITESIZE_H

#define TASK_COMM_LEN	16
#define DISK_NAME_LEN	32
#define MAX_SLOTS	20

#define MINORBITS	20
#define MINORMASK	((1U << MINORBITS) - 1)

#define MKDEV(ma, mi)	(((ma) << MINORBITS) | (mi))

struct hist_key {
	char comm[TASK_COMM_LEN];
};

struct hist {
	__u32 slots[MAX_SLOTS];
};

#endif /* __BITESIZE_H */

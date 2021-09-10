/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BIOLATENCY_H
#define __BIOLATENCY_H

#define DISK_NAME_LEN	32
#define MAX_SLOTS	27

#define MINORBITS	20
#define MINORMASK	((1U << MINORBITS) - 1)

#define MKDEV(ma, mi)	(((ma) << MINORBITS) | (mi))

struct hist_key {
	__u32 cmd_flags;
	__u32 dev;
};

struct hist {
	__u32 slots[MAX_SLOTS];
};

#endif /* __BIOLATENCY_H */

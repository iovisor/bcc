// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __BIOSNOOP_H
#define __BIOSNOOP_H

#define DISK_NAME_LEN	32
#define TASK_COMM_LEN	16
#define RWBS_LEN	8

#define MINORBITS	20
#define MINORMASK	((1U << MINORBITS) - 1)

#define MKDEV(ma, mi)	(((ma) << MINORBITS) | (mi))

struct event {
	char comm[TASK_COMM_LEN];
	__u64 delta;
	__u64 qdelta;
	__u64 ts;
	__u64 sector;
	__u32 len;
	__u32 pid;
	__u32 cmd_flags;
	__u32 dev;
};

#endif /* __BIOSNOOP_H */

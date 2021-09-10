/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BIOSTACKS_H
#define __BIOSTACKS_H

#define DISK_NAME_LEN	32
#define TASK_COMM_LEN	16
#define MAX_SLOTS	20
#define MAX_STACK	20

#define MINORBITS	20
#define MINORMASK	((1U << MINORBITS) - 1)

#define MKDEV(ma, mi)	(((ma) << MINORBITS) | (mi))

struct rqinfo {
	__u32 pid;
	int kern_stack_size;
	__u64 kern_stack[MAX_STACK];
	char comm[TASK_COMM_LEN];
	__u32 dev;
};

struct hist {
	__u32 slots[MAX_SLOTS];
};

#endif /* __BIOSTACKS_H */

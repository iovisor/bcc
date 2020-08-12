/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BIOSTACKS_H
#define __BIOSTACKS_H

#define DISK_NAME_LEN	32
#define TASK_COMM_LEN	16
#define MAX_SLOTS	20
#define MAX_STACK	20

struct rqinfo {
	__u32 pid;
	int kern_stack_size;
	__u64 start_ts;
	__u64 kern_stack[MAX_STACK];
	__u32 slots[MAX_SLOTS];
	char comm[TASK_COMM_LEN];
	char disk[DISK_NAME_LEN];
};

#endif /* __BIOSTACKS_H */

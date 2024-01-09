/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __SOLISTEN_H
#define __SOLISTEN_H

#define TASK_COMM_LEN	16

struct event {
	__u32 addr[4];
	__u32 pid;
	__u32 proto;
	int backlog;
	int ret;
	__u16 port;
	char task[TASK_COMM_LEN];
};

#endif /* __SOLISTEN_H */

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __RUNQSLOWER_H
#define __RUNQSLOWER_H

#define TASK_COMM_LEN 16

struct event {
	char task[TASK_COMM_LEN];
	char prev_task[TASK_COMM_LEN];
	__u64 delta_us;
	pid_t pid;
	pid_t prev_pid;
};

#endif /* __RUNQSLOWER_H */

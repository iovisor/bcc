/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __DRSNOOP_H
#define __DRSNOOP_H

#define TASK_COMM_LEN	16

struct event {
	char task[TASK_COMM_LEN];
	__u64 delta_ns;
	__u64 nr_reclaimed;
	__u64 nr_free_pages;
	pid_t pid;
};

#endif /* __DRSNOOP_H */

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __STATSNOOP_H
#define __STATSNOOP_H

#define TASK_COMM_LEN	16
#define NAME_MAX	255

struct event {
	__u64 ts_ns;
	__u32 pid;
	int ret;
	char comm[TASK_COMM_LEN];
	char pathname[NAME_MAX];
};

#endif /* __STATSNOOP_H */

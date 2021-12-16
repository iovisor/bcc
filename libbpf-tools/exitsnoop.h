/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __EXITSNOOP_H
#define __EXITSNOOP_H

#define TASK_COMM_LEN	16

struct event {
	__u64 start_time;
	__u64 exit_time;
	__u32 pid;
	__u32 tid;
	__u32 ppid;
	__u32 sig;
	int exit_code;
	char comm[TASK_COMM_LEN];
};

#endif /* __EXITSNOOP_H */

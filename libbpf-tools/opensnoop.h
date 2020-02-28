/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __OPENSNOOP_H
#define __OPENSNOOP_H

#define TASK_COMM_LEN 16
#define NAME_MAX 255

struct args_t {
	const char *fname;
	int flags;
};

struct event {
	/* user terminology for pid: */
	pid_t pid;
	__u64 ts;
	uid_t uid;
	int ret;
	char comm[TASK_COMM_LEN];
	char fname[NAME_MAX];
	int flags;
};

#endif /* __OPENSNOOP_H */

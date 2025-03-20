/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __STATSNOOP_H
#define __STATSNOOP_H

#define TASK_COMM_LEN	16
#define NAME_MAX	255

enum sys_type {
	SYS_STATFS = 1,
	SYS_NEWSTAT,
	SYS_STATX,
	SYS_NEWFSTAT,
	SYS_NEWFSTATAT,
	SYS_NEWLSTAT,
};

struct event {
	__u64 ts_ns;
	__u32 pid;
	enum sys_type type;
	int ret;
	char comm[TASK_COMM_LEN];

	/**
	 * fd: fstat(2)
	 * dirfd: statx(2), fstatat(2)
	 */
#define INVALID_FD	(-1)
	int fd;
	int dirfd;
	char pathname[NAME_MAX];
};

#endif /* __STATSNOOP_H */

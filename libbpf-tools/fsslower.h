/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __FSSLOWER_H
#define __FSSLOWER_H

#define FILE_NAME_LEN	32
#define TASK_COMM_LEN	16

enum fs_file_op {
	F_READ,
	F_WRITE,
	F_OPEN,
	F_FSYNC,
	F_MAX_OP,
};

struct event {
	__u64 delta_us;
	__u64 end_ns;
	__s64 offset;
	ssize_t size;
	pid_t pid;
	enum fs_file_op op;
	char file[FILE_NAME_LEN];
	char task[TASK_COMM_LEN];
};

#endif /* __FSSLOWER_H */

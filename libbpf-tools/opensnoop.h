/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __OPENSNOOP_H
#define __OPENSNOOP_H

#define TASK_COMM_LEN 16
#define NAME_MAX 255
#define INVALID_UID ((uid_t)-1)
#define MAX_PATH_DEPTH 32

struct args_t {
	const char *fname;
	int flags;
	__u32 mode;
};

struct event {
	/* user terminology for pid: */
	__u64 ts;
	pid_t pid;
	uid_t uid;
	int ret;
	int flags;
	__u32 mode;
	__u64 callers[2];
	char comm[TASK_COMM_LEN];

	/**
	 * Example: "/a/b/c/d"
	 * fname[]: "|d\0     |c\0     |b\0     |a\0     |       |..."
	 *           |NAME_MAX|
	 */
	char fname[NAME_MAX * MAX_PATH_DEPTH];
	__u32 path_depth;
	int get_path_failed;
};

#endif /* __OPENSNOOP_H */

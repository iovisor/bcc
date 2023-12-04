/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __FILELIFE_H
#define __FILELIFE_H

#define DNAME_INLINE_LEN	32
#define TASK_COMM_LEN		16

struct event {
	char file[DNAME_INLINE_LEN];
	char task[TASK_COMM_LEN];
	__u64 delta_ns;
	pid_t tgid;
	/* private */
	void *dentry;
};

#endif /* __FILELIFE_H */

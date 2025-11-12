/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __FUNCSLOWER_H
#define __FUNCSLOWER_H

#define TASK_COMM_LEN 16
#define MAX_ARGS 6
#define MAX_FUNCS 20

struct event {
	__u64 id;
	__u64 tgid_pid;
	__u64 start_ns;
	__u64 duration_ns;
	__s64 retval;
	char comm[TASK_COMM_LEN];
	__u64 args[MAX_ARGS];
	int user_stack_id;
	int kernel_stack_id;
};

#endif /* __FUNCSLOWER_H */

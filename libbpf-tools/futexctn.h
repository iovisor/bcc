/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __FUTEXCTN_H
#define __FUTEXCTN_H

#define TASK_COMM_LEN	16
#define MAX_SLOTS	36

struct hist_key {
	__u64 pid_tgid;
	__u64 uaddr;
	int user_stack_id;
};

struct hist {
	__u32 slots[MAX_SLOTS];
	char comm[TASK_COMM_LEN];
	__u64 contended;
	__u64 total_elapsed;
	__u64 min;
	__u64 max;
};

#endif /* FUTEXCTN_H_ */

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __LLCSTAT_H
#define __LLCSTAT_H

#define TASK_COMM_LEN	16

struct llcstat_value_info {
	__u64 ref;
	__u64 miss;
	char comm[TASK_COMM_LEN];
};

struct llcstat_key_info {
	__u32 cpu;
	__u32 pid;
	__u32 tid;
};

#endif /* __LLCSTAT_H */

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __LLCSTAT_H
#define __LLCSTAT_H

#define TASK_COMM_LEN	16

struct info {
	__u64 ref;
	__u64 miss;
	char comm[TASK_COMM_LEN];
};

#endif /* __LLCSTAT_H */

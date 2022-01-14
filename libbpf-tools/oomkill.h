/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __OOMKILL_H
#define __OOMKILL_H

#define TASK_COMM_LEN 16

struct data_t {
	__u32 fpid;
	__u32 tpid;
	__u64 pages;
	char fcomm[TASK_COMM_LEN];
	char tcomm[TASK_COMM_LEN];
};

#endif /* __OOMKILL_H */

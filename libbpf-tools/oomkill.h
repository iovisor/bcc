/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __OOMKILL_H
#define __OOMKILL_H

#define TASK_COMM_LEN	16

struct event {
	__u32 tpid;
	__u32 kpid;
	__u64 pages;
	char tcomm[TASK_COMM_LEN];
	char kcomm[TASK_COMM_LEN];
};

#endif /* __OOMKILL_H */

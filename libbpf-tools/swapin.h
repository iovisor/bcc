/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __SWAPIN_H
#define __SWAPIN_H

#define TASK_COMM_LEN 16

struct key_t {
	__u32 pid;
	char comm[TASK_COMM_LEN];
};

#endif /* __SWAPIN_H */

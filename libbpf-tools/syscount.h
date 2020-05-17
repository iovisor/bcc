// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Anton Protopopov
#ifndef __SYSCOUNT_H
#define __SYSCOUNT_H

#define MAX_ENTRIES 8192

#define TASK_COMM_LEN 16

struct data_t {
	__u64 count;
	__u64 total_ns;
	char comm[TASK_COMM_LEN];
};

#endif /* __SYSCOUNT_H */

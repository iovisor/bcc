// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021~2022 Hengqi Chen */
#ifndef __SIGSNOOP_H
#define __SIGSNOOP_H

#define TASK_COMM_LEN	16

struct event {
	__u32 pid;
	__u32 tpid;
	int sig;
	int ret;
	char comm[TASK_COMM_LEN];
	char tcomm[TASK_COMM_LEN];
};

#endif /* __SIGSNOOP_H */

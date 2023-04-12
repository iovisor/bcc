/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021~2022 Hengqi Chen */
#ifndef __MDFLUSH_H
#define __MDFLUSH_H

#define TASK_COMM_LEN	16
#define DISK_NAME_LEN	32

struct event {
	__u32 pid;
	char comm[TASK_COMM_LEN];
	char disk[DISK_NAME_LEN];
};

#endif /* __MDFLUSH_H */

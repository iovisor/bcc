// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Hengqi Chen */
#ifndef __TCPSTATES_H
#define __TCPSTATES_H

#define TASK_COMM_LEN	16

struct event {
	unsigned __int128 saddr;
	unsigned __int128 daddr;
	__u64 skaddr;
	__u64 ts_us;
	__u64 delta_us;
	__u32 pid;
	int oldstate;
	int newstate;
	__u16 family;
	__u16 sport;
	__u16 dport;
	char task[TASK_COMM_LEN];
};

#endif /* __TCPSTATES_H */

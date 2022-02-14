// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#ifndef __TCPACCEPT_H
#define __TCPACCEPT_H

#define TASK_COMM_LEN	16

struct event {
	unsigned __int128 saddr;
	unsigned __int128 daddr;
	__u64 ts_us;
	__u32 pid;
	__u16 lport;
	__u16 dport;
	__u8 family;
	char task[TASK_COMM_LEN];
};

#endif /* __TCPACCEPT_H */

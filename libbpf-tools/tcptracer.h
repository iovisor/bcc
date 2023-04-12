// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Microsoft Corporation
//
// Based on tcptracer(8) from BCC by Kinvolk GmbH and
// tcpconnect(8) by Anton Protopopov

#ifndef __TCPTRACER_H
#define __TCPTRACER_H

/* The maximum number of items in maps */
#define MAX_ENTRIES 8192

#define TASK_COMM_LEN 16

enum event_type {
	TCP_EVENT_TYPE_CONNECT,
	TCP_EVENT_TYPE_ACCEPT,
	TCP_EVENT_TYPE_CLOSE,
};

struct event {
	union {
		__u32 saddr_v4;
		unsigned __int128 saddr_v6;
	};
	union {
		__u32 daddr_v4;
		unsigned __int128 daddr_v6;
	};
	char task[TASK_COMM_LEN];
	__u64 ts_us;
	__u32 af; /* AF_INET or AF_INET6 */
	__u32 pid;
	__u32 uid;
	__u32 netns;
	__u16 dport;
	__u16 sport;
	__u8 type;
};


#endif /* __TCPTRACER_H */

/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2020 Anton Protopopov
 * Copyright (c) 2021 Red Hat, Inc.
 */
#ifndef __TCPRETRANS_H
#define __TCPRETRANS_H

#define MAX_ENTRIES 8192

#define RETRANSMIT  1
#define TLP         2

struct event {
	int type;
	int state;
	__u8 saddr[16];
	__u8 daddr[16];
	__u32 af; // AF_INET or AF_INET6
	__u32 pid;
	__u16 dport;
	__u16 sport;
};

struct ipv4_flow_key {
	__u32 saddr;
	__u32 daddr;
	__u16 dport;
	__u16 sport;
};

struct ipv6_flow_key {
	__u8 saddr[16];
	__u8 daddr[16];
	__u16 dport;
	__u16 sport;
};

#endif /* __TCPRETRANS_H */

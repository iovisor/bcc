/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __TCPTOP_H
#define __TCPTOP_H

#define TASK_COMM_LEN 16
#define MAX_ENTRIES 10240

struct ipv4_key_t {
    __u32 pid;
    __u32 saddr;
    __u32 daddr;
    __u16 lport;
    __u16 dport;
};

struct ipv6_key_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    __u32 pid;
    __u16 lport;
    __u16 dport;
    __u64 __pad__;
};

struct event {
	__u32 pid;
	union {
		__u32 saddr_v4;
		unsigned __int128 saddr_v6;
	};
	union {
		__u32 daddr_v4;
		unsigned __int128 daddr_v6;
	};
    __u16 sport;
    __u16 dport;
	int family; // AF_INET or AF_INET6
	char comm[TASK_COMM_LEN];
    bool is_send;
	union {
        int send_size;
        int recv_size;
	};
};

#endif /* __TCPTOP_H */

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __TCPTOP_H
#define __TCPTOP_H

#include <asm-generic/errno.h>

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

#define INET_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46

#define MAX_ENTRIES 8192

#define TASK_COMM_LEN 16

struct ipvx_key_t {
    __u32 pid;
    char name[TASK_COMM_LEN];
    union {
        __u32 saddr;
        __u8 saddr_v6[16];
    };
    union {
        __u32 daddr;
        __u8 daddr_v6[16];
    };
    __u16 lport;
    __u16 dport;
};

struct ipvx_node {
    struct ipvx_node *next;
    __u32 pid;
    char name[TASK_COMM_LEN];
    union {
        __u32 saddr;
        __u8 saddr_v6[16];
    };
    union {
        __u32 daddr;
        __u8 daddr_v6[16];
    };
    __u16 lport;
    __u16 dport;
    __u64 rx;
    __u64 tx;
};

#endif

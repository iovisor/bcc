/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __KILLSNOOP_H
#define __KILLSNOOP_H

#define TASK_COMM_LEN	16

struct event {
    __u32 pid;
    int ret;
    int tpid;
    int sig;
    char comm[TASK_COMM_LEN];
};

#endif /* __KILLSNOOP_H */

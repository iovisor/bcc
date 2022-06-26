/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __FUNCSLOWER_H
#define __FUNCSLOWER_H

#define MAX_PIDS 102400
#define PATH_MAX 4096
#define TASK_COMM_LEN 16
#define MAX_NUM_ARGS 5

struct entry_t {
        __u64 tgid;
        __u64 start_ns;
        __u64 args[MAX_NUM_ARGS];
};
struct data_t {
        __u32 id;
        __u64 tgid;
        __u64 start_ns;
        __u64 duration_ns;
        __u64 args[MAX_NUM_ARGS];
        __u64 retval;
        char comm[TASK_COMM_LEN];
        int ustack;
        int kstack;
};

enum units {
        NSEC,
        USEC,
        MSEC,
};

#endif /* __FUNCSLOWER_H */

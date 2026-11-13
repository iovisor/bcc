// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __STACKCOUNT_H
#define __STACKCOUNT_H

#define TASK_COMM_LEN 16
#define MAX_STACK_DEPTH 127

struct key_t {
	__u32 tgid;
	__s32 kernel_stack_id;
	__s32 user_stack_id;
	char name[TASK_COMM_LEN];
};

#endif /* __STACKCOUNT_H */

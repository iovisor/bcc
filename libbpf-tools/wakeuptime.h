/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#ifndef __WAKEUPTIME_H
#define __WAKEUPTIME_H

#define MAX_ENTRIES 10240
#define TASK_COMM_LEN 16

struct key_t {
	char waker[TASK_COMM_LEN];
	char target[TASK_COMM_LEN];
	int w_k_stack_id;
};

#endif /* __WAKEUPTIME_H */

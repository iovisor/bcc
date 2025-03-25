/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __KLOCKSTAT_H
#define __KLOCKSTAT_H

#define MAX_ENTRIES 102400
#define TASK_COMM_LEN 16
#define PERF_MAX_STACK_DEPTH 127

struct lock_stat {
	__u64 acq_count;
	__u64 acq_total_time;
	__u64 acq_max_time;
	__u64 acq_max_id;
	__u64 acq_max_lock_ptr;
	__u64 acq_max_nltype;
	__u64 acq_max_ioctl;
	char acq_max_comm[TASK_COMM_LEN];
	__u64 hld_count;
	__u64 hld_total_time;
	__u64 hld_max_time;
	__u64 hld_max_id;
	__u64 hld_max_lock_ptr;
	__u64 hld_max_nltype;
	__u64 hld_max_ioctl;
	char hld_max_comm[TASK_COMM_LEN];
};

#endif /*__KLOCKSTAT_H */

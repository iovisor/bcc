/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __CPUFREQ_H
#define __CPUFREQ_H

#define MAX_ENTRIES	1024
#define MAX_CPU_NR	128
#define MAX_SLOTS	26
#define TASK_COMM_LEN	16
#define HIST_STEP_SIZE	200

struct hkey {
	char comm[TASK_COMM_LEN];
};

struct hist {
	__u32 slots[MAX_SLOTS];
};

#endif /* __CPUFREQ_H */

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#ifndef __BPFSNOOP_H
#define __BPFSNOOP_H

#define TASK_COMM_LEN 16

struct event {
	pid_t pid;
	pid_t ppid;
	uid_t uid;
	__u32 insn_cnt;
	__u32 prog_type;
	char comm[TASK_COMM_LEN];
	char prog_name[TASK_COMM_LEN];
};

#endif /* __BPFSNOOP_H */

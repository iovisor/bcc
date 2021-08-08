/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __SIGSNOOP_H
#define __SIGSNOOP_H

#define TASK_COMM_LEN	16

enum sig_syscall {
	SYSCALL_KILL,
	SYSCALL_RT_SIGQUEUEINFO,
	SYSCALL_RT_TGSIGQUEUEINFO,
	SYSCALL_PIDFD_SEND_SIGNAL,
	SYSCALL_TGKILL,
	SYSCALL_TKILL,
};

struct event {
	__u32 pid;
	__u32 tpid;
	int sig;
	int ret;
	char comm[TASK_COMM_LEN];
	enum sig_syscall syscall;
};

#endif /* __SIGSNOOP_H */

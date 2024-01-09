// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//
// Copyright 2022 Sony Group Corporation

#ifndef __CAPABLE_H
#define __CAPABLE_H

#define TASK_COMM_LEN	16

struct cap_event {
	__u32	pid;
	__u32	cap;
	gid_t	tgid;
	uid_t	uid;
	int	audit;
	int	insetid;
	int	ret;
	char	task[TASK_COMM_LEN];
};

struct key_t {
	__u32	pid;
	__u32	tgid;
	int	user_stack_id;
	int	kern_stack_id;
};

enum uniqueness {
	UNQ_OFF, UNQ_PID, UNQ_CGROUP
};

#endif /* __CAPABLE_H */

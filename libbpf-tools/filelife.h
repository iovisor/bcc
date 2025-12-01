/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __FILELIFE_H
#define __FILELIFE_H

#include "path_helpers.h"

#define TASK_COMM_LEN		16

struct event {
	struct full_path fname;
	char task[TASK_COMM_LEN];
	__u64 delta_ns;
	pid_t tgid;
};

#endif /* __FILELIFE_H */

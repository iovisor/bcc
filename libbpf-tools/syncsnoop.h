/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __SYNCSNOOP_H
#define __SYNCSNOOP_H

#define TASK_COMM_LEN	16

enum sync_syscalls {
	SYS_T_MIN,
	SYS_SYNC,
	SYS_FSYNC,
	SYS_FDATASYNC,
	SYS_MSYNC,
	SYS_SYNC_FILE_RANGE,
	SYS_SYNC_FILE_RANGE2,
	SYS_ARM_SYNC_FILE_RANGE,
	SYS_SYNCFS,
	SYS_T_MAX,
};

struct event {
	char comm[TASK_COMM_LEN];
	__u64 ts_us;
	int sys;
};

static const char *sys_names[] = {
	"N/A",
	"sync",
	"fsync",
	"fdatasync",
	"msync",
	"sync_file_range",
	"sync_file_range2",
	"arm_sync_file_range",
	"syncfs",
	"N/A",
};

#endif /* __SYNCSNOOP_H */

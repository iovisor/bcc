/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BIOLATENCY_H
#define __BIOLATENCY_H

#define DISK_NAME_LEN	32
#define MAX_SLOTS	27

struct hist_key {
	char disk[DISK_NAME_LEN];
	__u32 cmd_flags;
};

struct hist {
	__u32 slots[MAX_SLOTS];
};

#endif /* __BIOLATENCY_H */

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __FSDIST_H
#define __FSDIST_H

enum fs_file_op {
	F_READ,
	F_WRITE,
	F_OPEN,
	F_FSYNC,
	F_GETATTR,
	F_MAX_OP,
};

#define MAX_SLOTS	32

struct hist {
	__u32 slots[MAX_SLOTS];
};

#endif /* __FSDIST_H */

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __XFSDIST_H
#define __XFSDIST_H

enum xfs_file_op {
	READ_ITER,
	WRITE_ITER,
	OPEN,
	FSYNC,
	MAX_OP,
};

#define MAX_SLOTS	27

struct hist {
	__u32 slots[MAX_SLOTS];
};

#endif /* __XFSDIST_H */

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __NFSDIST_H
#define __NFSDIST_H

enum nfs_file_op {
	READ,
	WRITE,
	OPEN,
	FSYNC,
	GETATTR,
	MAX_OP,
};

#define MAX_SLOTS	27

struct hist {
	__u32 slots[MAX_SLOTS];
};

#endif /* __NFSDIST_H */

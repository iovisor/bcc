/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __EXT4DIST_H
#define __EXT4DIST_H

enum ext4_fop_type {
	READ_ITER,
	WRITE_ITER,
	OPEN,
	FSYNC,
	__MAX_FOP_TYPE,
};

#define MAX_SLOTS	27

struct hist {
	__u32 slots[MAX_SLOTS];
};

#endif /* __EXT4DIST_H */

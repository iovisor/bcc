// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __READAHEAD_H
#define __READAHEAD_H

#define MAX_SLOTS	20

struct hist {
	__u32 unused;
	__u32 total;
	__u32 slots[MAX_SLOTS];
};

#endif /* __READAHEAD_H */

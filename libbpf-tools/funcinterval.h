// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Based on funcinterval.py from BCC by Edward Wu

#ifndef __FUNCINTERVAL_H
#define __FUNCINTERVAL_H

#define MAX_SLOTS	26

struct hist {
	__u32 slots[MAX_SLOTS];
};

#endif /* __FUNCINTERVAL_H */
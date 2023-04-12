/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TCPSYNBL_H
#define __TCPSYNBL_H

#define MAX_SLOTS 32

struct hist {
	__u32 slots[MAX_SLOTS];
};

#endif /* __TCPSYNBL_H */

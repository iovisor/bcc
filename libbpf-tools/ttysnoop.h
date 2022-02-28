/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TTYSNOOP_H
#define __TTYSNOOP_H

#define BUF_SIZE	4096

struct event {
	size_t count;
	char buf[BUF_SIZE];
};

#endif /* __TTYSNOOP_H */

// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __TTYSNOOP_H
#define __TTYSNOOP_H

#define BUFSIZE		256

struct event {
	char buf[BUFSIZE+1];
	size_t count;
};

#endif /* __TTYSNOOP_H */

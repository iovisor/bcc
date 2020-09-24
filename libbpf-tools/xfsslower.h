/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __XFSSLOWER_H
#define __XFSSLOWER_H

#define DNAME_INLINE_LEN	32
#define TASK_COMM_LEN		16

#define TRACE_READ   'R'
#define TRACE_WRITE  'W'
#define TRACE_OPEN   'O'
#define TRACE_FSYNC  'F'

struct event {
	char file[DNAME_INLINE_LEN];
	char task[TASK_COMM_LEN];
	__u64 delta_us;
	__u64 end_ns;
	__s64 offset;
	ssize_t size;
	pid_t tgid;
	char type;
};

#endif /* __DRSNOOP_H */

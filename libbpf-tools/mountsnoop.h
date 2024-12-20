/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __MOUNTSNOOP_H
#define __MOUNTSNOOP_H

#define TASK_COMM_LEN	16
#define FS_NAME_LEN	8
#define DATA_LEN	512
#define PATH_MAX	4096

enum op {
	OP_MIN, /* skip 0 */
	MOUNT,
	UMOUNT,
};

struct arg {
	__u64 ts;
	enum op op;

	union {
		/* op=MOUNT */
		struct {
			__u64 flags;
			const char *src;
			const char *dest;
			const char *fs;
			const char *data;
		} mount;
		/* op=UMOUNT */
		struct {
			__u64 flags;
			const char *dest;
		} umount;
	};
};

struct event {
	__u64 delta;
	__u32 pid;
	__u32 tid;
	unsigned int mnt_ns;
	int ret;
	enum op op;
	char comm[TASK_COMM_LEN];
	union {
		/* op=MOUNT */
		struct {
			__u64 flags;
			char fs[FS_NAME_LEN];
			char src[PATH_MAX];
			char dest[PATH_MAX];
			char data[DATA_LEN];
		} mount;
		/* op=UMOUNT */
		struct {
			__u64 flags;
			char dest[PATH_MAX];
		} umount;
	};
};

#endif /* __MOUNTSNOOP_H */

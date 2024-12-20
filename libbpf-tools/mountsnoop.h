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
	FSOPEN,
	FSCONFIG,
	FSMOUNT,
	MOVE_MOUNT,
};

union sys_arg {
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
	/* op=FSOPEN */
	struct {
		const char *fs;
		__u32 flags;
	} fsopen;
	/* op=FSCONFIG */
	struct {
		int fd;
		unsigned int cmd;
		const char *key;
		const char *value;
		int aux;
	} fsconfig;
	/* op=FSMOUNT */
	struct {
		int fs_fd;
		__u32 flags;
		__u32 attr_flags;
	} fsmount;
	/* op=MOVE_MOUNT */
	struct {
		int from_dfd;
		const char *from_pathname;
		int to_dfd;
		const char *to_pathname;
		__u32 flags;
	} move_mount;
};

struct arg {
	__u64 ts;
	enum op op;
	union sys_arg sys;
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
		/* op=FSOPEN */
		struct {
			char fs[FS_NAME_LEN];
			__u32 flags;
		} fsopen;
		/* op=FSCONFIG */
		struct {
			int fd;
			unsigned int cmd;
			char key[DATA_LEN];
			char value[DATA_LEN];
			int aux;
		} fsconfig;
		/* op=FSMOUNT */
		struct {
			int fs_fd;
			__u32 flags;
			__u32 attr_flags;
		} fsmount;
		/* op=MOVE_MOUNT */
		struct {
			int from_dfd;
			char from_pathname[PATH_MAX];
			int to_dfd;
			char to_pathname[PATH_MAX];
			__u32 flags;
		} move_mount;
	};
};

#endif /* __MOUNTSNOOP_H */

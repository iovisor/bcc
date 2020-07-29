#ifndef __BIOSNOOP_H
#define __BIOSNOOP_H

#define DISK_NAME_LEN	32
#define TASK_COMM_LEN	16
#define RWBS_LEN	8

struct event {
	char comm[TASK_COMM_LEN];
	__u64 delta;
	__u64 qdelta;
	__u64 ts;
	__u64 sector;
	__u32 len;
	__u32 pid;
	__u32 cmd_flags;
	char disk[DISK_NAME_LEN];
};

#endif /* __BIOSNOOP_H */

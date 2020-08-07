// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Alibaba Cloud
#ifndef SCHEDSNOOP_H
#define SCHEDSNOOP_H

#define NR_ENTRY_MAX		10000
#define NR_CPU_MAX		50
#define TASK_COMM_LEN		16
#define NR_MASK_MAX		64

enum {
	TYPE_MIGRATE,
	TYPE_ENQUEUE,
	TYPE_WAIT,
	TYPE_EXECUTE,
	TYPE_DEQUEUE,
	TYPE_SYSCALL_ENTER,
	TYPE_SYSCALL_EXIT,
};

enum {
	PREEMPTION,
	SYSCALL,
};

enum {
	MODE_EMPTY,
	MODE_TID,
	MODE_PID,
	MODE_MAX,
};

struct task_mask {
	__u64 mask;
};

struct cache_info {
	__u64 p_time;
	pid_t tid;
	int padding;
};

struct trace_info {
	int type;
	int cpu;
	int syscall;
	pid_t tid;
	__u64 ts;
	__u64 duration;
	char comm[TASK_COMM_LEN];
};

struct ti_key {
	int cpu;
	int syscall;
	pid_t tid;
	pid_t tgid;
	struct task_mask target;
	char comm[TASK_COMM_LEN];
};

struct run_info {
	__u64 p_time;
	struct ti_key run_ti_key;
};

struct stat_info {
	__u64 total;
	__u64 longest;
	int count;
	int padding;
};

struct stat_info_node {
	pid_t tid;
	int cpu;
	int count;
	__u64 avg;
	__u64 longest;
	char comm[4 * TASK_COMM_LEN];
};
#endif /* __SCHEDSNOOP_H */

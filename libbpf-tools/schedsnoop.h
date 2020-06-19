// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Alibaba Cloud
#ifndef SCHEDSNOOP_H
#define SCHEDSNOOP_H

#define NR_ENTRY_MAX		10000
#define TASK_COMM_LEN		16

enum {
	TYPE_MIGRATE,
	TYPE_ENQUEUE,
	TYPE_WAIT,
	TYPE_EXECUTE,
	TYPE_DEQUEUE,
	TYPE_SYSCALL_ENTER,
	TYPE_SYSCALL_EXIT,
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

struct si_key {
	int cpu;
	int syscall;
	pid_t pid;
};
#endif /* __SCHEDSNOOP_H */

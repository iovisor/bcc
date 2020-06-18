// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Alibaba Cloud
#ifndef SCHEDSNOOP_H
#define SCHEDSNOOP_H

#define NR_ENTRY_MAX		10000
#define NR_CPU_MAX		512
#define TASK_COMM_LEN		16


typedef unsigned long long u64;
typedef int pid_t;

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
	pid_t pid;
	u64 ts;
	char comm[TASK_COMM_LEN];
};

struct si_key {
	int cpu;
	int syscall;
	pid_t pid;
};
#endif /* __SCHEDSNOOP_H */

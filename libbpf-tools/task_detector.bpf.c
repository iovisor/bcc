// SPDX-Licence-Identifier: GPL-2.0
// Copyright (c) 2020 Wenhao Qu
//
// Based on task_detector by Yun Wang
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "task_detector.h"

#define DEBUG_ON 0
#define TASK_RUNNING 0x0000
#define TASK_REPORT_MAX 0x0100

struct{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct user_info);
} user_info_maps SEC(".maps");

struct{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NR_ENTRY_MAX);
	__type(key, int);
	__type(value, struct trace_info);
} trace_info_maps SEC(".maps");

struct{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, NR_ENTRY_MAX);
	__type(key, struct si_key);
	__type(value, u64);
} syscall_info_maps SEC(".maps");

struct{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} start_maps SEC(".maps");

struct{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} end_maps SEC(".maps");

struct{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} trace_on_maps SEC(".maps");

static inline void *get_user_info(void)
{
	int key = 0;

	return bpf_map_lookup_elem(&user_info_maps, &key);
}

static inline void set_trace_on(int cpu)
{
	int key = 0;
	int *trace_on = bpf_map_lookup_elem(&trace_on_maps, &key);

	if (trace_on)
		*trace_on = cpu + 1;
}

static inline void set_trace_off(void)
{
	int key = 0;
	int *trace_on = bpf_map_lookup_elem(&trace_on_maps, &key);

	if (trace_on)
		*trace_on = 0;
}

static inline int should_trace(int cpu)
{
	int key = 0;
	int *trace_on = bpf_map_lookup_elem(&trace_on_maps, &key);

	return (trace_on && *trace_on == cpu + 1);
}

static inline void *get_trace(int key)
{
	return bpf_map_lookup_elem(&trace_info_maps, &key);
}

static inline void add_trace(struct trace_info ti)
{
	int orig_end, key = 0;
	struct trace_info *tip;
	int *start, *end;

	start = bpf_map_lookup_elem(&start_maps, &key);
	end = bpf_map_lookup_elem(&end_maps, &key);

	if (!start || !end)
		return;

	orig_end = *end;
	*end = (*end + 1);

	if (*end == NR_ENTRY_MAX)
		*end = 0;

	if (*end == *start)
		return;

	//tip = get_trace(orig_end);
	//if (!tip) {
	//	*end = orig_end;
	//	return;
	//}

	//memcpy(tip, &ti, sizeof(ti));
	ti.ts = bpf_ktime_get_ns();

	if (ti.type == TYPE_SYSCALL_ENTER ||
	    ti.type == TYPE_SYSCALL_EXIT ||
	    ti.type == TYPE_WAIT ||
	    ti.type == TYPE_DEQUEUE)
		bpf_get_current_comm(&ti.comm, sizeof(ti.comm));
	bpf_map_update_elem(&trace_info_maps, &orig_end, &ti, 0);
}

SEC("tp_btf/sched_process_exit")
int handle__sched_process_exit(u64 *ctx)
{
	struct task_struct *p = (void *)ctx[0];
	struct user_info *ui = get_user_info();

	if (ui && ui->pid && ui->pid == p->pid)
		ui->exit = 1;

	return 0;
}

SEC("tp_btf/sched_migrate_task")
int handle__sched_migrate_task(u64 *ctx)
{
	struct task_struct *p = (void *) ctx[0];
	int dest_cpu = (int) ctx[1];
	struct trace_info ti = {
		.cpu = dest_cpu,
		.pid = p->pid,
		.type = TYPE_MIGRATE,
	};
	struct user_info *ui = get_user_info();

	if (!ui || !ui->pid || ui->pid != p->pid)
		return 0;

	set_trace_on(dest_cpu);

	add_trace(ti);

	return 0;
}

SEC("tp_btf/sched_wakeup")
int handle__sched_wakeup(u64 *ctx)
{
	struct task_struct *p = (void *) ctx[0];
	//int target_cpu = task_cpu(p);
	struct trace_info ti = {
		.cpu = p->wake_cpu,
		.pid = p->pid,
		.type = TYPE_ENQUEUE,
	};
	struct user_info *ui = get_user_info();

	if (!ui || !ui->pid || ui->pid != p->pid)
		return 0;

	set_trace_on(p->wake_cpu);

	add_trace(ti);

	return 0;
}

SEC("tp_btf/sched_switch")
int handle__sched_switch(u64 *ctx)
{
	struct task_struct *prev = (void *) ctx[1];
	struct task_struct *next = (void *) ctx[2];
	struct trace_info ti = {
		.cpu = bpf_get_smp_processor_id(),
	}, *tip;
	struct user_info *ui = get_user_info();

	if (!ui || !ui->pid)
		return 0;

	if (!should_trace(ti.cpu)) {
		if (ui->pid != prev->pid &&
		    ui->pid != next->pid)
			return 0;

		set_trace_on(ti.cpu);

		ti.pid = ui->pid;
		ti.type = TYPE_MIGRATE;
		add_trace(ti);
	}

	if (prev->state != TASK_RUNNING &&
	    prev->state != TASK_REPORT_MAX) {
		if (ui->pid == prev->pid)
			set_trace_off();
		ti.type = TYPE_DEQUEUE;
	} else
		ti.type = TYPE_WAIT;
	ti.pid = prev->pid;
	add_trace(ti);

	if (!should_trace(ti.cpu))
		return 0;

	ti.type = TYPE_EXECUTE;
	ti.pid = next->pid,
	add_trace(ti);

	return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int bpf_trace_sys_enter(struct trace_event_raw_sys_enter *args)
{
	struct trace_info ti = {
		.cpu = bpf_get_smp_processor_id(),
		.pid = bpf_get_current_pid_tgid(),
		.type = TYPE_SYSCALL_ENTER,
		.syscall = args->id,
	}, *tip;
	struct user_info *ui = get_user_info();

	if (args->id && ui && ui->trace_syscall && should_trace(ti.cpu))
		add_trace(ti);

	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int bpf_trace_sys_exit(struct trace_event_raw_sys_exit *args)
{
	struct trace_info ti = {
		.cpu = bpf_get_smp_processor_id(),
		.pid = bpf_get_current_pid_tgid(),
		.type = TYPE_SYSCALL_EXIT,
		.syscall = args->id,
	}, *tip;
	struct user_info *ui = get_user_info();

	if (args->id && ui && ui->trace_syscall && should_trace(ti.cpu))
		add_trace(ti);

	return 0;
}

char _license[] SEC("license") = "GPL";

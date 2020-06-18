// SPDX-Licence-Identifier: GPL-2.0
// Copyright (c) 2020 Alibaba Cloud
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "schedsnoop.h"

#define DEBUG_ON 0
#define TASK_RUNNING 0x0000
#define TASK_REPORT_MAX 0x0100

const volatile pid_t targ_pid = 0;
const volatile int trace_syscall = 0;
volatile bool targ_exit = false;
volatile int trace_on = 0;

struct{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

struct{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, NR_ENTRY_MAX);
	__type(key, struct si_key);
	__type(value, u64);
} syscall_info_maps SEC(".maps");

static inline void set_trace_on(int cpu)
{
	trace_on = cpu + 1;
}

static inline void set_trace_off(void)
{
	trace_on = 0;
}

static inline int should_trace(int cpu)
{
	return (trace_on == cpu + 1);
}

static inline void add_trace(void *ctx, struct trace_info* ti)
{
	ti->ts = bpf_ktime_get_ns();
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, ti, sizeof(*ti));
}

SEC("tp_btf/sched_process_exit")
int handle__sched_process_exit(u64 *ctx)
{
	struct task_struct *p = (void *)ctx[0];

	if (targ_pid && targ_pid == p->pid)
		targ_exit = true;

	return 0;
}

SEC("tp_btf/sched_migrate_task")
int handle__sched_migrate_task(u64 *ctx)
{
	struct task_struct *p = (void *) ctx[0];
	int dest_cpu = (int) ctx[1];

	if (!targ_pid || targ_pid != p->pid)
		return 0;

	struct trace_info ti = {
		.cpu = dest_cpu,
		.pid = p->pid,
		.type = TYPE_MIGRATE,
	};

	bpf_get_current_comm(&ti.comm, sizeof(ti.comm));	

	set_trace_on(dest_cpu);
	
	add_trace(ctx, &ti);

	return 0;
}

SEC("tp_btf/sched_wakeup")
int handle__sched_wakeup(u64 *ctx)
{
	struct task_struct *p = (void *) ctx[0];

	if (!targ_pid || targ_pid != p->pid)
		return 0;

	struct trace_info ti = {
		.cpu = p->wake_cpu,
		.pid = p->pid,
		.type = TYPE_ENQUEUE,
	};

	bpf_probe_read_kernel_str(&ti.comm, sizeof(ti.comm), p->comm);

	set_trace_on(p->wake_cpu);

	add_trace(ctx, &ti);

	return 0;
}

SEC("tp_btf/sched_switch")
int handle__sched_switch(u64 *ctx)
{
	struct task_struct *prev = (void *) ctx[1];
	struct task_struct *next = (void *) ctx[2];
	
	if (!targ_pid)
		return 0;

	struct trace_info ti = {
		.cpu = bpf_get_smp_processor_id(),
	}, *tip;

	if (!should_trace(ti.cpu)) {
		if (targ_pid != prev->pid &&
		    targ_pid != next->pid)
			return 0;

		set_trace_on(ti.cpu);

		ti.pid = targ_pid;
		ti.type = TYPE_MIGRATE;
		add_trace(ctx, &ti);
	}

	if (prev->state != TASK_RUNNING &&
	    prev->state != TASK_REPORT_MAX) {
		if (targ_pid == prev->pid)
			set_trace_off();
		ti.type = TYPE_DEQUEUE;
	} else
		ti.type = TYPE_WAIT;

	ti.pid = prev->pid;
	bpf_probe_read_kernel_str(&ti.comm, sizeof(ti.comm), prev->comm);
	add_trace(ctx, &ti);

	if (!should_trace(ti.cpu))
		return 0;

	ti.type = TYPE_EXECUTE;
	ti.pid = next->pid;
	bpf_probe_read_kernel_str(&ti.comm, sizeof(ti.comm), next->comm);
	add_trace(ctx, &ti);

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

	bpf_get_current_comm(&ti.comm, sizeof(ti.comm));
	if (args->id && trace_syscall && should_trace(ti.cpu))
		add_trace(args, &ti);

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

	bpf_get_current_comm(&ti.comm, sizeof(ti.comm));
	if (args->id && trace_syscall && should_trace(ti.cpu))
		add_trace(args, &ti);

	return 0;
}

char _license[] SEC("license") = "GPL";

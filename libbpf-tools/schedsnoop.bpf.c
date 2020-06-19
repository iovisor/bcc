// SPDX-Licence-Identifier: GPL-2.0
// Copyright (c) 2020 Alibaba Cloud
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "schedsnoop.h"

#define TASK_RUNNING 0x0000
#define TASK_REPORT_MAX 0x0100

const volatile pid_t targ_pid = 0;
const volatile int trace_syscall = 0;
bool targ_exit = false;
int trace_on = -1;

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

static __always_inline void set_trace_on(int cpu)
{
	trace_on = cpu;
}

static __always_inline void set_trace_off(void)
{
	trace_on = -1;
}

static __always_inline int should_trace(int cpu)
{
	return trace_on == cpu;
}

static __always_inline void emit_trace(void *ctx, struct trace_info* ti)
{
	ti->ts = bpf_ktime_get_ns();
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, ti, sizeof(*ti));
}

static __always_inline void emit_and_update(void *ctx, struct trace_info* ti,
	       	struct si_key* sik)
{
	__u64 *last_ts;
	__u64 ts = bpf_ktime_get_ns();
	switch (ti->type) {
	case TYPE_SYSCALL_ENTER:
		bpf_map_update_elem(&syscall_info_maps, sik, &ts, BPF_ANY);
		break;
	case TYPE_SYSCALL_EXIT:
		last_ts = bpf_map_lookup_elem(&syscall_info_maps, sik);
		if(!last_ts)
			return;
		ti->duration = ts - *last_ts;
		bpf_map_delete_elem(&syscall_info_maps, sik);
		break;
	default:
		break;
	}

	ti->ts = ts;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, ti, sizeof(*ti));
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(handle__sched_process_exit, struct task_struct *p)
{
	if (targ_pid && targ_pid == p->pid)
		targ_exit = true;

	return 0;
}

SEC("tp_btf/sched_migrate_task")
int BPF_PROG(handle__sched_migrate_task, struct task_struct *p, int dest_cpu)
{
	if (targ_pid != p->pid)
		return 0;

	struct trace_info ti = {
		.cpu = dest_cpu,
		.pid = p->pid,
		.type = TYPE_MIGRATE,
	};

	bpf_probe_read_kernel_str(&ti.comm, sizeof(ti.comm), p->comm);

	set_trace_on(dest_cpu);
	
	emit_trace(ctx, &ti);

	return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(handle__sched_wakeup, struct task_struct *p)
{
	if (targ_pid != p->pid)
		return 0;

	struct trace_info ti = {
		.cpu = p->wake_cpu,
		.pid = p->pid,
		.type = TYPE_ENQUEUE,
	};

	bpf_probe_read_kernel_str(&ti.comm, sizeof(ti.comm), p->comm);

	set_trace_on(p->wake_cpu);

	emit_trace(ctx, &ti);

	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(handle__sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	struct trace_info ti = {
		.cpu = bpf_get_smp_processor_id(),
	};

	/*
	 * During the pressure test, sometimes we may lose recording
	 * the sched_migrate event and some unexpected sched_switch 
	 * events with our target thread included may exist on the 
	 * untargeted cpu.
	 *
	 * We add this check to avoid losing too much information 
	 * when the situation discussed above happens.
	 */
	if (!should_trace(ti.cpu)) {
		if (targ_pid != prev->pid &&
		    targ_pid != next->pid)
			return 0;

		set_trace_on(ti.cpu);

		ti.pid = targ_pid;
		ti.type = TYPE_MIGRATE;
		bpf_probe_read_kernel_str(&ti.comm, sizeof(ti.comm), prev->comm);
		emit_trace(ctx, &ti);
	}
	
	/*
	 * Check the previous status to find out whether the previous
	 * task is preempted or not.
	 *
	 * If the previous status is TASK_RUNNING or TASK_REPORT_MAX,
	 * then there is a preemption and we set the trace type as
	 * TYPE_WAIT.
	 *
	 * Otherwise, the previous task actively dequeues and we set
	 * the trace type as TYPE_DEQUEUE.
	 */
	if (prev->state != TASK_RUNNING &&
	    prev->state != TASK_REPORT_MAX) {
		if (targ_pid == prev->pid)
			set_trace_off();
		ti.type = TYPE_DEQUEUE;
	} else {
		ti.type = TYPE_WAIT;
	}

	ti.pid = prev->pid;
	bpf_probe_read_kernel_str(&ti.comm, sizeof(ti.comm), prev->comm);
	emit_trace(ctx, &ti);

	if (!should_trace(ti.cpu))
		return 0;

	ti.type = TYPE_EXECUTE;
	ti.pid = next->pid;
	bpf_probe_read_kernel_str(&ti.comm, sizeof(ti.comm), next->comm);
	emit_trace(ctx, &ti);

	return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int bpf_trace_sys_enter(struct trace_event_raw_sys_enter *args)
{
	int cpu = bpf_get_smp_processor_id();

	if (args->id && trace_syscall && should_trace(cpu)) {
		struct trace_info ti = {
			.cpu = cpu,
			.pid = bpf_get_current_pid_tgid(),
			.type = TYPE_SYSCALL_ENTER,
			.syscall = args->id,
		};
		bpf_get_current_comm(&ti.comm, sizeof(ti.comm));

		struct si_key sik = {
			.cpu = cpu,
			.pid = ti.pid,
			.syscall = args->id,
		};

		emit_and_update(args, &ti, &sik);
	}

	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int bpf_trace_sys_exit(struct trace_event_raw_sys_exit *args)
{
	int cpu = bpf_get_smp_processor_id();

	if (args->id && trace_syscall && should_trace(cpu)) {
		struct trace_info ti = {
			.cpu = cpu,
			.pid = bpf_get_current_pid_tgid(),
			.type = TYPE_SYSCALL_EXIT,
			.syscall = args->id,
		};
		bpf_get_current_comm(&ti.comm, sizeof(ti.comm));

		struct si_key sik = {
			.cpu = cpu,
			.pid = ti.pid,
			.syscall = args->id,
		};

		emit_and_update(args, &ti, &sik);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";

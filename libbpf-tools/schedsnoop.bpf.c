// SPDX-Licence-Identifier: GPL-2.0
// Copyright (c) 2020 Alibaba Cloud
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "schedsnoop.h"

#define TASK_RUNNING 0x0000
#define TASK_REPORT_MAX 0x0100

const volatile pid_t targ_tid = 0;
const volatile pid_t cur_tid = 0;
const volatile bool trace_syscall = false;
const volatile bool output_log = false;
bool targ_exit = false;
int trace_on = -1;
int stat_count = 0;
int sys_count = 0;
__u64 p_time = 0;

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, NR_ENTRY_MAX);
	__type(key, struct ti_key);
	__type(value, u64);
} trace_info_maps SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, NR_ENTRY_MAX);
	__type(key, struct ti_key);
	__type(value, struct stat_info);
} trace_stat_maps SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, NR_ENTRY_MAX);
	__type(key, struct ti_key);
	__type(value, struct stat_info);
} syscall_stat_maps SEC(".maps");

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

static __always_inline void update_stat_info(void *map, struct ti_key *tik, __u64 duration)
{
	struct stat_info *stat = bpf_map_lookup_elem(map, tik);
	if (!stat) {
		struct stat_info tmp = {
			.count = 1,
			.total = duration,
			.longest = duration,
		};
		bpf_map_update_elem(map, tik, &tmp, BPF_ANY);
		if (map == &trace_stat_maps)
			stat_count += 1;
		else
			sys_count += 1;
	} else {
		stat->count = stat->count + 1;
		stat->total = stat->total + duration;
		stat->longest = stat->longest > duration ? stat->longest : duration;
	}
}

static __always_inline void handle_trace(void *ctx, struct ti_key *tik, int type)
{
	__u64 ts = bpf_ktime_get_ns();
	__u64 duration = 0, *last_ts;
	switch (type) {
	case TYPE_MIGRATE:
	case TYPE_ENQUEUE:
		p_time = ts;
		break;
	case TYPE_EXECUTE:
		if (tik->tid != targ_tid)
			p_time = ts;
		break;
	case TYPE_WAIT:
		if (tik->tid != targ_tid) {
			duration = ts - p_time;
			bpf_map_delete_elem(&trace_info_maps, tik);
			update_stat_info(&trace_stat_maps, tik, duration);
		}
		break;
	case TYPE_DEQUEUE:
		if (tik->tid != targ_tid) {
			duration = ts - p_time;
			bpf_map_delete_elem(&trace_info_maps, tik);
			update_stat_info(&trace_stat_maps, tik, duration);
		}
		break;
	case TYPE_SYSCALL_ENTER:
		bpf_map_update_elem(&trace_info_maps, tik, &ts, BPF_ANY);
		break;
	case TYPE_SYSCALL_EXIT:
		last_ts = bpf_map_lookup_elem(&trace_info_maps, tik);
		if(!last_ts)
			return;
		duration = ts - *last_ts;
		bpf_map_delete_elem(&trace_info_maps, tik);
		update_stat_info(&syscall_stat_maps, tik, duration);
		break;
	}

	if (output_log) {
		/*
		 * The perf buffer is used to emit the events to user-space and
		 * print them. During this process, the SYSCALL "epoll_wait" is
		 * called to check the buffer.
		 *
		 * When tracing SYSCALL with this tool, there will be an endless 
		 * loop. 
		 *
		 * emit event -------> user space capture the event
		 *    /|\                           |
		 *     |                           \|/
		 * new event <------- SYSCALL "epoll_wait" called
		 *
		 * Thus, an extra condition is added here to avoid emit the 
		 * SYSCALL "epoll_wait" events which are called by schedsnoop 
		 * itself. These events won't output to the console, but they
		 * will still be recorded in statistic information.
		 */
		if ((tik->syscall == 232 || tik->syscall == 1) && tik->tid == cur_tid)
			return;

		struct trace_info ti = {
			.type = type,
			.cpu = tik->cpu,
			.syscall = tik->syscall,
			.tid = tik->tid,
			.ts = ts,
			.duration = duration,
		};
		bpf_probe_read_kernel_str(&ti.comm, sizeof(ti.comm), tik->comm);

		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ti, sizeof(ti));
	}
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(handle__sched_process_exit, struct task_struct *p)
{
	if (targ_tid == p->pid)
		targ_exit = true;

	return 0;
}

SEC("tp_btf/sched_migrate_task")
int BPF_PROG(handle__sched_migrate_task, struct task_struct *p, int dest_cpu)
{
	if (targ_tid != p->pid)
		return 0;

	struct ti_key tik = {
		.cpu = dest_cpu,
		.tid = p->pid,
		.syscall = -1,
	};

	bpf_probe_read_kernel_str(&tik.comm, sizeof(tik.comm), p->comm);

	set_trace_on(dest_cpu);
	
	handle_trace(ctx, &tik, TYPE_MIGRATE);

	return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(handle__sched_wakeup, struct task_struct *p)
{
	if (targ_tid != p->pid)
		return 0;

	struct ti_key tik = {
		.cpu = p->wake_cpu,
		.tid = p->pid,
		.syscall = -1,
	};

	bpf_probe_read_kernel_str(&tik.comm, sizeof(tik.comm), p->comm);

	set_trace_on(p->wake_cpu);

	handle_trace(ctx, &tik, TYPE_ENQUEUE);

	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(handle__sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	struct ti_key tik = {
		.cpu = bpf_get_smp_processor_id(),
		.syscall = -1,
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
	if (!should_trace(tik.cpu)) {
		if (targ_tid != prev->pid &&
		    targ_tid != next->pid)
			return 0;

		set_trace_on(tik.cpu);

		tik.tid = targ_tid;
		bpf_probe_read_kernel_str(&tik.comm, sizeof(tik.comm), prev->comm);
		handle_trace(ctx, &tik, TYPE_MIGRATE);
	}
	
	tik.tid = prev->pid;
	bpf_probe_read_kernel_str(&tik.comm, sizeof(tik.comm), prev->comm);

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
		if (targ_tid == prev->pid)
			set_trace_off();
		handle_trace(ctx, &tik, TYPE_DEQUEUE);
	} else {
		handle_trace(ctx, &tik, TYPE_WAIT);
	}

	if (!should_trace(tik.cpu))
		return 0;

	tik.tid = next->pid;
	bpf_probe_read_kernel_str(&tik.comm, sizeof(tik.comm), next->comm);
	handle_trace(ctx, &tik, TYPE_EXECUTE);

	return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int bpf_trace_sys_enter(struct trace_event_raw_sys_enter *args)
{
	if(!args->id || !trace_syscall)
		return 0;

	int cpu = bpf_get_smp_processor_id();
	if (should_trace(cpu)) {
		struct ti_key tik = {
			.cpu = cpu,
			.tid = bpf_get_current_pid_tgid(),
			.syscall = args->id,
		};
		bpf_get_current_comm(&tik.comm, sizeof(tik.comm));

		handle_trace(args, &tik, TYPE_SYSCALL_ENTER);
	}

	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int bpf_trace_sys_exit(struct trace_event_raw_sys_exit *args)
{
	if(!args->id || !trace_syscall)
		return 0;

	int cpu = bpf_get_smp_processor_id();
	if (should_trace(cpu)) {
		struct ti_key tik = {
			.cpu = cpu,
			.tid = bpf_get_current_pid_tgid(),
			.syscall = args->id,
		};
		bpf_get_current_comm(&tik.comm, sizeof(tik.comm));

		handle_trace(args, &tik, TYPE_SYSCALL_EXIT);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";

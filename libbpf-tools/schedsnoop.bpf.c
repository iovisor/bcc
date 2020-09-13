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
const volatile int mode = MODE_EMPTY;
const volatile bool trace_syscall = false;
const volatile bool output_log = false;
bool targ_exit = false;
int trace_on = -1;
int stat_count = 0;
int sys_count = 0;
int targ_num = 0;
int exit_count = 0;
__u64 p_time = 0;

//events: map for perf output
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

//trace_time_maps: traced task(ti_key)-timestamp(u64)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, NR_ENTRY_MAX);
	__type(key, struct ti_key);
	__type(value, u64);
} trace_time_maps SEC(".maps");

//trace_stat_maps: traced task(ti_key)-statistic info(stat_info)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, NR_ENTRY_MAX);
	__type(key, struct ti_key);
	__type(value, struct stat_info);
} trace_stat_maps SEC(".maps");

//syscall_stat_maps: traced syscall(ti_key)-statistic info(stat_info)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, NR_ENTRY_MAX);
	__type(key, struct ti_key);
	__type(value, struct stat_info);
} syscall_stat_maps SEC(".maps");

//mast_task_maps: mask index(int)-task id(pid_t)
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NR_MASK_MAX);
	__type(key, int);
	__type(value, pid_t);
} mask_task_maps SEC(".maps");

//task_mask_maps: task id(pid_t)-mask index(int)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, NR_MASK_MAX);
	__type(key, pid_t);
	__type(value, int);
} task_mask_maps SEC(".maps");

//task_cpu_maps: task id(pid_t)-cpu(int)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, NR_MASK_MAX);
	__type(key, pid_t);
	__type(value, int);
} task_cpu_maps SEC(".maps");

//cpu_current_maps: cpu(int)-current working task(run_info)
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NR_CPU_MAX);
	__type(key, int);
	__type(value, struct run_info);
} cpu_current_maps SEC(".maps");

//cpu_cache_maps: cpu(int)-target task that has benn migrated currently(cache_info)
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NR_CPU_MAX);
	__type(key, int);
	__type(value, struct cache_info);
} cpu_cache_maps SEC(".maps");

//cpu_worklist_maps: cpu(int)-target tasks that work on this cpu(task_mask)
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NR_CPU_MAX);
	__type(key, int);
	__type(value, struct task_mask);
} cpu_worklist_maps SEC(".maps");

static __always_inline int check(struct task_struct *p)
{
	int ret = 0;

	switch (mode) {
	case MODE_TID:
		if (targ_tid && targ_tid == p->pid)
			ret = 1;
		break;
	case MODE_PID:
		if (targ_tid && targ_tid == p->tgid)
			ret = 1;
		break;
	default:
		break;
	}
	
	return ret;
}

static __always_inline struct task_mask *get_cpu_workmask(int cpu)
{
	struct task_mask *cpu_mask;

	cpu_mask = bpf_map_lookup_elem(&cpu_worklist_maps, &cpu);
/*
	if (!cpu_mask) {
		struct task_mask tmp;

		bpf_map_update_elem(&cpu_worklist_maps, &cpu, &tmp, BPF_ANY);
		cpu_mask = bpf_map_lookup_elem(&cpu_worklist_maps, &cpu);
	}
*/
	return cpu_mask;
}

static __always_inline void mask_add(struct task_mask *mask, int idx, struct task_mask *output)
{
	u64 task_mask;

	if (!output)
		return;

	task_mask = 1 << idx;
	if (mask)
		output->mask = mask->mask | task_mask;
	else
		output->mask = task_mask;
}

static __always_inline void mask_remove(struct task_mask *mask, int idx, struct task_mask *output)
{
	u64 task_mask;

	if (!mask || !output)
		return;

	task_mask = 1 << idx;
	if (mask->mask & task_mask)
		output->mask = mask->mask ^ task_mask;
	else
		output->mask = mask->mask;
}

static __always_inline int check_mask(struct task_mask *mask)
{
	return (mask && mask->mask > 0) ? 1 : 0;
}

static __always_inline int get_mask_idx(pid_t tid)
{
	int *idx = bpf_map_lookup_elem(&task_mask_maps, &tid);
	int ret, key = 0;

	if (!idx) {
		ret = targ_num++;

		bpf_map_update_elem(&task_mask_maps, &tid, &ret, BPF_ANY);
		bpf_map_update_elem(&mask_task_maps, &ret, &tid, BPF_ANY);
	} else {
		ret = *idx;
	}

	return ret;
}

static __always_inline int should_trace(int cpu)
{
	struct task_mask *cpu_mask = get_cpu_workmask(cpu);

	return check_mask(cpu_mask);
}

static __always_inline void set_trace_on(pid_t tid, int cpu)
{
	struct task_mask *cpu_mask = get_cpu_workmask(cpu);
	int idx, key = 0;

	if (!cpu_mask)
		return;

	idx = get_mask_idx(tid);
	mask_add(cpu_mask, idx, cpu_mask);
	bpf_map_update_elem(&task_cpu_maps, &tid, &cpu, BPF_ANY);
}

static __always_inline void set_trace_off(pid_t tid)
{
	int *orig_cpu = bpf_map_lookup_elem(&task_cpu_maps, &tid);

	if (orig_cpu) {
		struct task_mask *orig_mask = get_cpu_workmask(*orig_cpu);
		int idx, key = 0;

		if (!orig_mask)
			return;

		idx = get_mask_idx(tid);
		mask_remove(orig_mask, idx, orig_mask);

		if (!check_mask(orig_mask)) {
			struct run_info *ri = bpf_map_lookup_elem(&cpu_current_maps, orig_cpu);

			if (ri)
				ri->p_time = 0;
		}

	}
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

static __always_inline void handle_trace(void *ctx, struct ti_key *tik, int orig_cpu, int type)
{
	__u64 ts = bpf_ktime_get_ns();
	__u64 duration = 0, *last_ts;
	struct run_info *ri;
	struct cache_info *ci;
	int cpu = tik->cpu;

	switch (type) {
	case TYPE_MIGRATE:
		ri = bpf_map_lookup_elem(&cpu_current_maps, &orig_cpu);
		if (ri && ri->p_time) {
			int idx = get_mask_idx(tik->tid);
			struct task_mask tmp;

			mask_add(&tmp, idx, &tmp);
			ri->run_ti_key.target = tmp;

			duration = ts - ri->p_time;
			update_stat_info(&trace_stat_maps, &ri->run_ti_key, duration);
		}
	case TYPE_ENQUEUE:
		if (ts) {
			struct cache_info tmp_ci = {
				.tid = tik->tid,
				.p_time = ts,
			};

			bpf_map_update_elem(&cpu_cache_maps, &cpu, &tmp_ci, BPF_ANY);
		}
		break;
	case TYPE_EXECUTE:
		if (ts) {
			struct run_info tmp_ri = {
				.p_time = ts,
				.run_ti_key = *tik,
			};

			bpf_map_update_elem(&cpu_current_maps, &cpu, &tmp_ri, BPF_ANY);
		}
		break;
	case TYPE_WAIT:
	case TYPE_DEQUEUE:
		ri = bpf_map_lookup_elem(&cpu_current_maps, &cpu);
		ci = bpf_map_lookup_elem(&cpu_cache_maps, &cpu);

		if (ri && ri->p_time) {
			struct task_mask *tmp = get_cpu_workmask(cpu);

			if (tmp) {
				tik->target = *tmp;
				if (orig_cpu) {
					int idx = get_mask_idx(tik->tid);

					mask_remove(&tik->target, idx, &tik->target);
				}

				if (check_mask(&tik->target)) {
					duration = ts - ri->p_time;
					update_stat_info(&trace_stat_maps, tik, duration);
				}
			}

			ri->p_time = 0;
		}

		if (ci && ci->p_time) {
			int idx = get_mask_idx(ci->tid);
			struct task_mask tmp;

			mask_add(&tmp, idx, &tmp);
			tik->target = tmp;

			duration = ts - ci->p_time;
			update_stat_info(&trace_stat_maps, tik, duration);

			set_trace_on(ci->tid, cpu);

			ci->p_time = 0;
		}
		break;
	case TYPE_SYSCALL_ENTER:
		bpf_map_update_elem(&trace_time_maps, tik, &ts, BPF_ANY);
		break;
	case TYPE_SYSCALL_EXIT:
		last_ts = bpf_map_lookup_elem(&trace_time_maps, tik);
		if(!last_ts)
			return;
		duration = ts - *last_ts;
		bpf_map_delete_elem(&trace_time_maps, tik);
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
	if (check(p)) {
		exit_count++;

		if (exit_count >= targ_num)
			targ_exit = true;
	}

	return 0;
}

SEC("tp_btf/sched_migrate_task")
int BPF_PROG(handle__sched_migrate_task, struct task_struct *p, int dest_cpu)
{
	if (!check(p))
		return 0;

	struct ti_key tik = {
		.cpu = dest_cpu,
		.tid = p->pid,
		.syscall = -1,
	};

	bpf_probe_read_kernel_str(&tik.comm, sizeof(tik.comm), p->comm);
	
	set_trace_off(tik.tid);
	
	handle_trace(ctx, &tik, p->cpu, TYPE_MIGRATE);

	return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(handle__sched_wakeup, struct task_struct *p)
{
	if (!check(p))
		return 0;

	struct ti_key tik = {
		.cpu = p->wake_cpu,
		.tid = p->pid,
		.syscall = -1,
	};

	bpf_probe_read_kernel_str(&tik.comm, sizeof(tik.comm), p->comm);

	set_trace_on(tik.tid, tik.cpu);

	handle_trace(ctx, &tik, 0, TYPE_ENQUEUE);

	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(handle__sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	struct ti_key tik = {
		.cpu = bpf_get_smp_processor_id(),
		.syscall = -1,
	};
	int is_prev = check(prev);
	int is_next = check(next);

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
		if (!is_prev && !is_next)
			return 0;

		if (is_prev) {
			set_trace_off(prev->pid);
			set_trace_on(prev->pid, tik.cpu);
		}

		if (is_next) {
			set_trace_off(next->pid);
			set_trace_on(next->pid, tik.cpu);
		}
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
	if (prev->state != TASK_RUNNING && !preempt) {
		handle_trace(ctx, &tik, is_prev, TYPE_DEQUEUE);
		if (is_prev)
			set_trace_off(prev->pid);
	} else {
		handle_trace(ctx, &tik, is_prev, TYPE_WAIT);
	}

	if (!should_trace(tik.cpu))
		return 0;

	tik.tid = next->pid;
	bpf_probe_read_kernel_str(&tik.comm, sizeof(tik.comm), next->comm);
	handle_trace(ctx, &tik, 0, TYPE_EXECUTE);

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

		handle_trace(args, &tik, 0, TYPE_SYSCALL_ENTER);
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

		handle_trace(args, &tik, 0, TYPE_SYSCALL_EXIT);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";

// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021~2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "sigsnoop.h"

#define MAX_ENTRIES	10240

const volatile pid_t filtered_pid = 0;
const volatile int target_signals = 0;
const volatile bool failed_only = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct event);
} values SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

static __always_inline bool is_target_signal(int sig)
{
	if (target_signals == 0)
		return true;

	if ((target_signals & (1 << (sig - 1))) == 0)
		return false;

	return true;
}

static __always_inline void get_tcomm(pid_t tpid, char *tcomm, __u32 size)
{
	if (bpf_ksym_exists(bpf_task_from_pid)) {
		struct task_struct *ttask = bpf_task_from_pid(tpid);
		if (ttask) {
			bpf_probe_read_kernel(tcomm, size, ttask->comm);
			bpf_task_release(ttask);
			return;
		}
	}
	tcomm[0] = 'N';
	tcomm[1] = '/';
	tcomm[2] = 'A';
	tcomm[3] = '\0';
}

static int probe_entry(pid_t tpid, int sig)
{
	struct event event = {};
	__u64 pid_tgid;
	__u32 pid, tid;

        if (!is_target_signal(sig))
          return 0;

        pid_tgid = bpf_get_current_pid_tgid();
        pid = pid_tgid >> 32;
	tid = (__u32)pid_tgid;
	if (filtered_pid && pid != filtered_pid)
		return 0;

	get_tcomm(tpid, event.tcomm, sizeof(event.tcomm));

	event.pid = pid;
	event.tpid = tpid;
	event.sig = sig;
	bpf_get_current_comm(event.comm, sizeof(event.comm));
	bpf_map_update_elem(&values, &tid, &event, BPF_ANY);
	return 0;
}

static int probe_exit(void *ctx, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)pid_tgid;
	struct event *eventp;

	eventp = bpf_map_lookup_elem(&values, &tid);
	if (!eventp)
		return 0;

	if (failed_only && ret >= 0)
		goto cleanup;

	eventp->ret = ret;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, eventp, sizeof(*eventp));

cleanup:
	bpf_map_delete_elem(&values, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int kill_entry(struct syscall_trace_enter *ctx)
{
	pid_t tpid = (pid_t)ctx->args[0];
	int sig = (int)ctx->args[1];

	return probe_entry(tpid, sig);
}

SEC("tracepoint/syscalls/sys_exit_kill")
int kill_exit(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_tkill")
int tkill_entry(struct syscall_trace_enter *ctx)
{
	pid_t tpid = (pid_t)ctx->args[0];
	int sig = (int)ctx->args[1];

	return probe_entry(tpid, sig);
}

SEC("tracepoint/syscalls/sys_exit_tkill")
int tkill_exit(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_tgkill")
int tgkill_entry(struct syscall_trace_enter *ctx)
{
	pid_t tpid = (pid_t)ctx->args[1];
	int sig = (int)ctx->args[2];

	return probe_entry(tpid, sig);
}

SEC("tracepoint/syscalls/sys_exit_tgkill")
int tgkill_exit(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, ctx->ret);
}

SEC("tracepoint/signal/signal_generate")
int sig_trace(struct trace_event_raw_signal_generate *ctx)
{
	struct event event = {};
	pid_t tpid = ctx->pid;
	int ret = ctx->errno;
	int sig = ctx->sig;
	__u64 pid_tgid;
	__u32 pid;

	if (failed_only && ret == 0)
		return 0;
        if (!is_target_signal(sig))
          return 0;

        pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	if (filtered_pid && pid != filtered_pid)
		return 0;

	get_tcomm(tpid, event.tcomm, sizeof(event.tcomm));

	event.pid = pid;
	event.tpid = tpid;
	event.sig = sig;
	event.ret = ret;
	bpf_get_current_comm(event.comm, sizeof(event.comm));
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "sigsnoop.h"

#define MAX_ENTRIES	10240

const volatile pid_t target_pid = 0;
const volatile int target_signal = 0;
const volatile bool failed_only = false;
const volatile bool kill_only = false;

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

static int probe_entry(pid_t target_pid, int sig, enum sig_syscall syscall)
{
	__u64 pid_tgid;
	__u32 pid, tid;
	struct event event = {};

	if (kill_only && syscall != SYSCALL_KILL)
		return 0;

	if (target_signal && target_signal != sig)
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	tid = (__u32)pid_tgid;
	if (target_pid && target_pid != pid)
		return 0;

	event.pid = pid;
	event.tpid = target_pid;
	event.sig = sig;
	event.syscall = syscall;
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
int kill_entry(struct trace_event_raw_sys_enter *ctx)
{
	pid_t target_pid = (pid_t)ctx->args[0];
	int sig = (int)ctx->args[1];

	return probe_entry(target_pid, sig, SYSCALL_KILL);
}

SEC("tracepoint/syscalls/sys_exit_kill")
int kill_exit(struct trace_event_raw_sys_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_rt_sigqueueinfo")
int rt_sigqueueinfo_entry(struct trace_event_raw_sys_enter *ctx)
{
	pid_t target_pid = (pid_t)ctx->args[0];
	int sig = (int)ctx->args[1];

	return probe_entry(target_pid, sig, SYSCALL_RT_SIGQUEUEINFO);
}

SEC("tracepoint/syscalls/sys_exit_rt_sigqueueinfo")
int rt_sigqueueinfo_exit(struct trace_event_raw_sys_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_rt_tgsigqueueinfo")
int rt_tgsigqueueinfo_entry(struct trace_event_raw_sys_enter *ctx)
{
	pid_t target_pid = (pid_t)ctx->args[1];
	int sig = (int)ctx->args[2];

	return probe_entry(target_pid, sig, SYSCALL_RT_TGSIGQUEUEINFO);
}

SEC("tracepoint/syscalls/sys_exit_rt_tgsigqueueinfo")
int rt_tgsigqueueinfo_exit(struct trace_event_raw_sys_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_pidfd_send_signal")
int pidfd_send_signal_entry(struct trace_event_raw_sys_enter *ctx)
{
	int pidfd = (int)ctx->args[0];
	int sig = (int)ctx->args[1];

	return probe_entry(pidfd, sig, SYSCALL_PIDFD_SEND_SIGNAL);
}

SEC("tracepoint/syscalls/sys_exit_pidfd_send_signal")
int pidfd_send_signal_exit(struct trace_event_raw_sys_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_tgkill")
int tgkill_entry(struct trace_event_raw_sys_enter *ctx)
{
	pid_t target_pid = (pid_t)ctx->args[1];
	int sig = (int)ctx->args[2];

	return probe_entry(target_pid, sig, SYSCALL_TGKILL);
}

SEC("tracepoint/syscalls/sys_exit_tgkill")
int tgkill_exit(struct trace_event_raw_sys_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_tkill")
int tkill_entry(struct trace_event_raw_sys_enter *ctx)
{
	pid_t target_pid = (pid_t)ctx->args[0];
	int sig = (int)ctx->args[1];

	return probe_entry(target_pid, sig, SYSCALL_TKILL);
}

SEC("tracepoint/syscalls/sys_exit_tkill")
int tkill_exit(struct trace_event_raw_sys_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

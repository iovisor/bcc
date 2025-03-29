// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Hengqi Chen
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "statsnoop.h"

#define MAX_ENTRIES 10240

const volatile pid_t target_pid = 0;
const volatile bool  trace_failed_only = false;

struct value {
	int fd;
	int dirfd;
	const char *pathname;
	enum sys_type type;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct value);
} values SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

static int probe_entry(void *ctx, enum sys_type type, int fd, int dirfd,
		       const char *pathname)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 pid = id >> 32;
	__u32 tid = (__u32)id;
	struct value value = {};

	if (!pathname && fd == INVALID_FD && dirfd == INVALID_FD)
		return 0;

	if (target_pid && target_pid != pid)
		return 0;

	value.fd = fd;
	value.dirfd = dirfd;
	value.pathname = pathname;
	value.type = type;

	bpf_map_update_elem(&values, &tid, &value, BPF_ANY);
	return 0;
};

static int probe_return(void *ctx, int ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 pid = id >> 32;
	__u32 tid = (__u32)id;
	struct event event = {};
	struct value *pvalue;

	pvalue = bpf_map_lookup_elem(&values, &tid);
	if (!pvalue)
		return 0;

	if (trace_failed_only && ret >= 0) {
		bpf_map_delete_elem(&values, &tid);
		return 0;
	}

	event.pid = pid;
	event.ts_ns = bpf_ktime_get_ns();
	event.ret = ret;
	event.type = pvalue->type;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	event.fd = pvalue->fd;
	event.dirfd = pvalue->dirfd;
	if (pvalue->pathname)
		bpf_probe_read_user_str(event.pathname, sizeof(event.pathname),
					pvalue->pathname);
	else
		event.pathname[0] = '\0';

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	bpf_map_delete_elem(&values, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_statfs")
int handle_statfs_entry(struct syscall_trace_enter *ctx)
{
	return probe_entry(ctx, SYS_STATFS, INVALID_FD, INVALID_FD,
			   (const char *)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_statfs")
int handle_statfs_return(struct syscall_trace_exit *ctx)
{
	return probe_return(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_newstat")
int handle_newstat_entry(struct syscall_trace_enter *ctx)
{
	return probe_entry(ctx, SYS_NEWSTAT, INVALID_FD, INVALID_FD,
			   (const char *)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_newstat")
int handle_newstat_return(struct syscall_trace_exit *ctx)
{
	return probe_return(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_statx")
int handle_statx_entry(struct syscall_trace_enter *ctx)
{
	return probe_entry(ctx, SYS_STATX, INVALID_FD, (int)ctx->args[0],
			   (const char *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_exit_statx")
int handle_statx_return(struct syscall_trace_exit *ctx)
{
	return probe_return(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_newfstat")
int handle_newfstat_entry(struct syscall_trace_enter *ctx)
{
	return probe_entry(ctx, SYS_NEWFSTAT, (int)ctx->args[0], INVALID_FD,
			   NULL);
}

SEC("tracepoint/syscalls/sys_exit_newfstat")
int handle_newfstat_return(struct syscall_trace_exit *ctx)
{
	return probe_return(ctx, (int)ctx->ret);
}


SEC("tracepoint/syscalls/sys_enter_newfstatat")
int handle_newfstatat_entry(struct syscall_trace_enter *ctx)
{
	return probe_entry(ctx, SYS_NEWFSTATAT, INVALID_FD, (int)ctx->args[0],
			   (const char *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_exit_newfstatat")
int handle_newfstatat_return(struct syscall_trace_exit *ctx)
{
	return probe_return(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_newlstat")
int handle_newlstat_entry(struct syscall_trace_enter *ctx)
{
	return probe_entry(ctx, SYS_NEWLSTAT, INVALID_FD, INVALID_FD,
			   (const char *)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_newlstat")
int handle_newlstat_return(struct syscall_trace_exit *ctx)
{
	return probe_return(ctx, (int)ctx->ret);
}

char LICENSE[] SEC("license") = "GPL";

// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 Tiago Ilieve
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "syncsnoop.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");


static void __syscall(struct trace_event_raw_sys_enter *ctx,
		      enum sync_syscalls sys)
{
	struct event event = {};

	bpf_get_current_comm(event.comm, sizeof(event.comm));
	event.ts_us = bpf_ktime_get_ns() / 1000;
	event.sys = sys;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
}

SEC("tracepoint/syscalls/sys_enter_sync")
void tracepoint__syscalls__sys_enter_sync(struct trace_event_raw_sys_enter *ctx)
{
	__syscall(ctx, SYS_SYNC);
}

SEC("tracepoint/syscalls/sys_enter_fsync")
void tracepoint__syscalls__sys_enter_fsync(struct trace_event_raw_sys_enter *ctx)
{
	__syscall(ctx, SYS_FSYNC);
}

SEC("tracepoint/syscalls/sys_enter_fdatasync")
void tracepoint__syscalls__sys_enter_fdatasync(struct trace_event_raw_sys_enter *ctx)
{
	__syscall(ctx, SYS_FDATASYNC);
}

SEC("tracepoint/syscalls/sys_enter_msync")
void tracepoint__syscalls__sys_enter_msync(struct trace_event_raw_sys_enter *ctx)
{
	__syscall(ctx, SYS_MSYNC);
}

SEC("tracepoint/syscalls/sys_enter_sync_file_range")
void tracepoint__syscalls__sys_enter_sync_file_range(struct trace_event_raw_sys_enter *ctx)
{
	__syscall(ctx, SYS_SYNC_FILE_RANGE);
}

SEC("tracepoint/syscalls/sys_enter_syncfs")
void tracepoint__syscalls__sys_enter_syncfs(struct trace_event_raw_sys_enter *ctx)
{
	__syscall(ctx, SYS_SYNCFS);
}

char LICENSE[] SEC("license") = "GPL";

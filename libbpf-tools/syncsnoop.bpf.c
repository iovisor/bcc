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

SEC("tracepoint/syscalls/sys_enter_sync")
void tracepoint__syscalls__sys_enter_sync(struct trace_event_raw_sys_enter *ctx)
{
	struct event event = {};

	event.ts_us = bpf_ktime_get_ns() / 1000;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
}

char LICENSE[] SEC("license") = "GPL";

// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

#include "mysqld_qslower.h"

#define MAX_ENTRIES	10240

const volatile __u64 lat_ns = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct start);
} starts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

static int handle_start(const char *query)
{
	__u32 tid = bpf_get_current_pid_tgid();
	struct start start = {};

	start.ts = bpf_ktime_get_ns();
	start.query = query;
	bpf_map_update_elem(&starts, &tid, &start, BPF_ANY);
	return 0;
}

static int handle_done(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 pid = id >> 32;
	__u32 tid = (__u32)id;
	struct event event = {};
	struct start *start;
	__u64 lat;

	start = bpf_map_lookup_elem(&starts, &tid);
	if (!start)
		return 0;

	bpf_map_delete_elem(&starts, &tid);

	lat = bpf_ktime_get_ns() - start->ts;
	if (lat < lat_ns)
		return 0;

	event.ts = start->ts;
	event.lat_ns = lat;
	event.pid = pid;
	bpf_probe_read_user_str(event.query, sizeof(event.query), start->query);
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

SEC("usdt")
int BPF_USDT(query_start, const char *query)
{
	return handle_start(query);
}

SEC("usdt")
int BPF_USDT(query_done)
{
	return handle_done(ctx);
}

char LICENSE[] SEC("license") = "GPL";

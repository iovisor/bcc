/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2021 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "gethostlatency.h"

#define MAX_ENTRIES	10240

const volatile pid_t target_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct event);
} starts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

static int probe_entry(struct pt_regs *ctx)
{
	if (!PT_REGS_PARM1(ctx))
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct event event = {};

	if (target_pid && target_pid != pid)
		return 0;

	event.time = bpf_ktime_get_ns();
	event.pid = pid;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	bpf_probe_read_user(&event.host, sizeof(event.host), (void *)PT_REGS_PARM1(ctx));
	bpf_map_update_elem(&starts, &tid, &event, BPF_ANY);
	return 0;
}

static int probe_return(struct pt_regs *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct event *eventp;

	eventp = bpf_map_lookup_elem(&starts, &tid);
	if (!eventp)
		return 0;

	/* update time from timestamp to delta */
	eventp->time = bpf_ktime_get_ns() - eventp->time;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, eventp, sizeof(*eventp));
	bpf_map_delete_elem(&starts, &tid);
	return 0;
}

SEC("uprobe")
int BPF_UPROBE(handle_entry)
{
	return probe_entry(ctx);
}

SEC("uretprobe")
int BPF_URETPROBE(handle_return)
{
	return probe_return(ctx);
}

char LICENSE[] SEC("license") = "GPL";

// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Hengqi Chen
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "gethostlatency.h"

#define MAX_ENTRIES 10240

const volatile pid_t targ_tgid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct val_t);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

static __always_inline
int probe_entry(struct pt_regs *ctx) {
	if (!PT_REGS_PARM1(ctx))
		return 0;

	struct val_t val = {};
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (targ_tgid && targ_tgid != pid)
		return 0;

	if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
		bpf_probe_read_user(&val.host, sizeof(val.host),
					   (void *)PT_REGS_PARM1(ctx));
		val.pid = pid;
		val.time = bpf_ktime_get_ns();
		bpf_map_update_elem(&start, &pid, &val, BPF_ANY);
	}

	return 0;
}

static __always_inline
int probe_return(struct pt_regs *ctx) {
	struct val_t *valp;
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	__u64 now = bpf_ktime_get_ns();

	valp = bpf_map_lookup_elem(&start, &pid);
	if (!valp)
		return 0;

	// update time from timestamp to delta
	valp->time = now - valp->time;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, valp,
			sizeof(*valp));
	bpf_map_delete_elem(&start, &pid);
	return 0;
}

SEC("kprobe/handle_entry")
int handle_entry(struct pt_regs *ctx)
{
	return probe_entry(ctx);
}

SEC("kretprobe/handle_return")
int handle_return(struct pt_regs *ctx)
{
	return probe_return(ctx);
}

char LICENSE[] SEC("license") = "GPL";

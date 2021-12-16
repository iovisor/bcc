// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, u64);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} start SEC(".maps");

__u64 latency = 0;
__u64 num = 0;

SEC("fentry/migrate_misplaced_page")
int BPF_PROG(migrate_misplaced_page)
{
	u32 pid = bpf_get_current_pid_tgid();
	u64 ts = bpf_ktime_get_ns();

	bpf_map_update_elem(&start, &pid, &ts, 0);
	return 0;
}

SEC("fexit/migrate_misplaced_page")
int BPF_PROG(migrate_misplaced_page_exit)
{
	u32 pid = bpf_get_current_pid_tgid();
	u64 *tsp, ts = bpf_ktime_get_ns();
	s64 delta;

	tsp = bpf_map_lookup_elem(&start, &pid);
	if (!tsp)
		return 0;
	delta = (s64)(ts - *tsp);
	if (delta < 0)
		goto cleanup;
	__sync_fetch_and_add(&latency, delta / 1000000U);
	__sync_fetch_and_add(&num, 1);

cleanup:
	bpf_map_delete_elem(&start, &pid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

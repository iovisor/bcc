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
} start SEC(".maps");

__u64 latency = 0;
__u64 num = 0;

static int __migrate_misplaced(void)
{
	u32 pid = bpf_get_current_pid_tgid();
	u64 ts = bpf_ktime_get_ns();

	bpf_map_update_elem(&start, &pid, &ts, 0);
	return 0;
}

SEC("fentry/migrate_misplaced_page")
int BPF_PROG(fentry_migrate_misplaced_page)
{
	return __migrate_misplaced();
}

SEC("fentry/migrate_misplaced_folio")
int BPF_PROG(fentry_migrate_misplaced_folio)
{
	return __migrate_misplaced();
}

SEC("kprobe/migrate_misplaced_page")
int BPF_PROG(kprobe_migrate_misplaced_page)
{
	return __migrate_misplaced();
}

SEC("kprobe/migrate_misplaced_folio")
int BPF_PROG(kprobe_migrate_misplaced_folio)
{
	return __migrate_misplaced();
}

static int __migrate_misplaced_exit(void)
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

SEC("fexit/migrate_misplaced_page")
int BPF_PROG(fexit_migrate_misplaced_page_exit)
{
	return __migrate_misplaced_exit();
}

SEC("fexit/migrate_misplaced_folio")
int BPF_PROG(fexit_migrate_misplaced_folio_exit)
{
	return __migrate_misplaced_exit();
}

SEC("kretprobe/migrate_misplaced_page")
int BPF_PROG(kretprobe_migrate_misplaced_page_exit)
{
	return __migrate_misplaced_exit();
}

SEC("kretprobe/migrate_misplaced_folio")
int BPF_PROG(kretprobe_migrate_misplaced_folio_exit)
{
	return __migrate_misplaced_exit();
}

char LICENSE[] SEC("license") = "GPL";

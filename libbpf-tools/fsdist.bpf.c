/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bits.bpf.h"
#include "fsdist.h"

#define MAX_ENTRIES	10240

const volatile pid_t target_pid = 0;
const volatile bool in_ms = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, __u64);
} starts SEC(".maps");

struct hist hists[F_MAX_OP] = {};

static int probe_entry()
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	__u64 ts;

	if (target_pid && target_pid != pid)
		return 0;

	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&starts, &tid, &ts, BPF_ANY);
	return 0;
}

static int probe_return(enum fs_file_op op)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 ts = bpf_ktime_get_ns();
	__u64 *tsp, slot;
	__s64 delta;

	tsp = bpf_map_lookup_elem(&starts, &tid);
	if (!tsp)
		return 0;

	if (op >= F_MAX_OP)
		goto cleanup;

	delta = (__s64)(ts - *tsp);
	if (delta < 0)
		goto cleanup;

	if (in_ms)
		delta /= 1000000;
	else
		delta /= 1000;

	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&hists[op].slots[slot], 1);

cleanup:
	bpf_map_delete_elem(&starts, &tid);
	return 0;
}

SEC("kprobe/dummy_file_read")
int BPF_KPROBE(file_read_entry)
{
	return probe_entry();
}

SEC("kretprobe/dummy_file_read")
int BPF_KRETPROBE(file_read_exit)
{
	return probe_return(F_READ);
}

SEC("kprobe/dummy_file_write")
int BPF_KPROBE(file_write_entry)
{
	return probe_entry();
}

SEC("kretprobe/dummy_file_write")
int BPF_KRETPROBE(file_write_exit)
{
	return probe_return(F_WRITE);
}

SEC("kprobe/dummy_file_open")
int BPF_KPROBE(file_open_entry)
{
	return probe_entry();
}

SEC("kretprobe/dummy_file_open")
int BPF_KRETPROBE(file_open_exit)
{
	return probe_return(F_OPEN);
}

SEC("kprobe/dummy_file_sync")
int BPF_KPROBE(file_sync_entry)
{
	return probe_entry();
}

SEC("kretprobe/dummy_file_sync")
int BPF_KRETPROBE(file_sync_exit)
{
	return probe_return(F_FSYNC);
}

SEC("kprobe/dummy_getattr")
int BPF_KPROBE(getattr_entry)
{
	return probe_entry();
}

SEC("kretprobe/dummy_getattr")
int BPF_KRETPROBE(getattr_exit)
{
	return probe_return(F_GETATTR);
}

SEC("fentry/dummy_file_read")
int BPF_PROG(file_read_fentry)
{
	return probe_entry();
}

SEC("fexit/dummy_file_read")
int BPF_PROG(file_read_fexit)
{
	return probe_return(F_READ);
}

SEC("fentry/dummy_file_write")
int BPF_PROG(file_write_fentry)
{
	return probe_entry();
}

SEC("fexit/dummy_file_write")
int BPF_PROG(file_write_fexit)
{
	return probe_return(F_WRITE);
}

SEC("fentry/dummy_file_open")
int BPF_PROG(file_open_fentry)
{
	return probe_entry();
}

SEC("fexit/dummy_file_open")
int BPF_PROG(file_open_fexit)
{
	return probe_return(F_OPEN);
}

SEC("fentry/dummy_file_sync")
int BPF_PROG(file_sync_fentry)
{
	return probe_entry();
}

SEC("fexit/dummy_file_sync")
int BPF_PROG(file_sync_fexit)
{
	return probe_return(F_FSYNC);
}

SEC("fentry/dummy_getattr")
int BPF_PROG(getattr_fentry)
{
	return probe_entry();
}

SEC("fexit/dummy_getattr")
int BPF_PROG(getattr_fexit)
{
	return probe_return(F_GETATTR);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

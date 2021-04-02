// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "bits.bpf.h"
#include "ext4dist.h"

const volatile bool targ_ms = false;
const volatile pid_t targ_tgid = 0;

#define MAX_ENTRIES	10240

struct hist hists[__MAX_FOP_TYPE] = {};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, u64);
} starts SEC(".maps");

static int trace_entry(void)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	u32 pid = id;
	u64 ts;

	if (targ_tgid && targ_tgid != tgid)
		return 0;
	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&starts, &pid, &ts, BPF_ANY);

	return 0;
}

SEC("kprobe/ext4_file_read_iter")
int BPF_KPROBE(kprobe1)
{
	return trace_entry();
}

SEC("kprobe/ext4_file_write_iter")
int BPF_KPROBE(kprobe2)
{
	return trace_entry();
}

SEC("kprobe/ext4_file_open")
int BPF_KPROBE(kprobe3)
{
	return trace_entry();
}

SEC("kprobe/ext4_sync_file")
int BPF_KPROBE(kprobe4)
{
	return trace_entry();
}

SEC("fentry/ext4_file_read_iter")
int BPF_PROG(fentry1)
{
	return trace_entry();
}

SEC("fentry/ext4_file_write_iter")
int BPF_PROG(fentry2)
{
	return trace_entry();
}

SEC("fentry/ext4_file_open")
int BPF_PROG(fentry3)
{
	return trace_entry();
}

SEC("fentry/ext4_sync_file")
int BPF_PROG(fentry4)
{
	return trace_entry();
}

static int trace_return(enum ext4_fop_type type)
{
	u64 *tsp, slot, ts = bpf_ktime_get_ns();
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id;
	s64 delta;

	tsp = bpf_map_lookup_elem(&starts, &pid);
	if (!tsp)
		return 0;
	delta = (s64)(ts - *tsp);
	if (delta < 0)
		goto cleanup;

	if (targ_ms)
		delta /= 1000000U;
	else
		delta /= 1000U;
	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	if (type >= __MAX_FOP_TYPE)
		goto cleanup;
	__sync_fetch_and_add(&hists[type].slots[slot], 1);

cleanup:
	bpf_map_delete_elem(&starts, &pid);
	return 0;
}

SEC("kretprobe/ext4_file_read_iter")
int BPF_KRETPROBE(kretprobe1)
{
	return trace_return(READ_ITER);
}

SEC("kretprobe/ext4_file_write_iter")
int BPF_KRETPROBE(kretprobe2)
{
	return trace_return(WRITE_ITER);
}

SEC("kretprobe/ext4_file_open")
int BPF_KRETPROBE(kretprobe3)
{
	return trace_return(OPEN);
}

SEC("kretprobe/ext4_sync_file")
int BPF_KRETPROBE(kretprobe4)
{
	return trace_return(FSYNC);
}

SEC("fexit/ext4_file_read_iter")
int BPF_PROG(fexit1)
{
	return trace_return(READ_ITER);
}

SEC("fexit/ext4_file_write_iter")
int BPF_PROG(fexit2)
{
	return trace_return(WRITE_ITER);
}

SEC("fexit/ext4_file_open")
int BPF_PROG(fexit3)
{
	return trace_return(OPEN);
}

SEC("fexit/ext4_sync_file")
int BPF_PROG(fexit4)
{
	return trace_return(FSYNC);
}

char LICENSE[] SEC("license") = "GPL";

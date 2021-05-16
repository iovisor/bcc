// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Hengqi Chen
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bits.bpf.h"
#include "nfsdist.h"

#define MAX_ENTRIES		10240

const volatile pid_t target_pid = 0;
const volatile bool in_ms = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, __u64);
} starts SEC(".maps");

struct hist hists[MAX_OP] = {};

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

static int probe_return(enum nfs_file_op op)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	__u64 ts = bpf_ktime_get_ns();
	__u64 *tsp, slot;
	__s64 delta;

	tsp = bpf_map_lookup_elem(&starts, &tid);
	if (!tsp)
		return 0;

	if (op >= MAX_OP)
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

SEC("kprobe/nfs_file_read")
int BPF_KPROBE(nfs_file_read_entry)
{
	return probe_entry();
}

SEC("kretprobe/nfs_file_read")
int BPF_KRETPROBE(nfs_file_read_return)
{
	return probe_return(READ);
}

SEC("kprobe/nfs_file_write")
int BPF_KPROBE(nfs_file_write_entry)
{
	return probe_entry();
}

SEC("kretprobe/nfs_file_write")
int BPF_KRETPROBE(nfs_file_write_return)
{
	return probe_return(WRITE);
}

SEC("kprobe/nfs_file_open")
int BPF_KPROBE(nfs_file_open_entry)
{
	return probe_entry();
}

SEC("kretprobe/nfs_file_open")
int BPF_KRETPROBE(nfs_file_open_return)
{
	return probe_return(OPEN);
}

SEC("kprobe/nfs_file_fsync")
int BPF_KPROBE(nfs_file_fsync_entry)
{
	return probe_entry();
}

SEC("kretprobe/nfs_file_fsync")
int BPF_KRETPROBE(nfs_file_fsync_return)
{
	return probe_return(OPEN);
}

SEC("kprobe/nfs_getattr")
int BPF_KPROBE(nfs_getattr_entry)
{
	return probe_entry();
}

SEC("kretprobe/nfs_getattr")
int BPF_KRETPROBE(nfs_getattr_return)
{
	return probe_return(GETATTR);
}

SEC("fentry/nfs_file_read")
int BPF_PROG(nfs_file_read_fentry)
{
	return probe_entry();
}

SEC("fexit/nfs_file_read")
int BPF_PROG(nfs_file_read_fexit)
{
	return probe_return(READ);
}

SEC("fentry/nfs_file_write")
int BPF_PROG(nfs_file_write_fentry)
{
	return probe_entry();
}

SEC("fexit/nfs_file_write")
int BPF_PROG(nfs_file_write_fexit)
{
	return probe_return(WRITE);
}

SEC("fentry/nfs_file_open")
int BPF_PROG(nfs_file_open_fentry)
{
	return probe_entry();
}

SEC("fexit/nfs_file_open")
int BPF_PROG(nfs_file_open_fexit)
{
	return probe_return(OPEN);
}

SEC("fentry/nfs_file_fsync")
int BPF_PROG(nfs_file_fsync_fentry)
{
	return probe_entry();
}

SEC("fexit/nfs_file_fsync")
int BPF_PROG(nfs_file_fsync_fexit)
{
	return probe_return(OPEN);
}

SEC("fentry/nfs_getattr")
int BPF_PROG(nfs_getattr_fentry)
{
	return probe_entry();
}

SEC("fexit/nfs_getattr")
int BPF_PROG(nfs_getattr_fexit)
{
	return probe_return(GETATTR);
}

char LICENSE[] SEC("license") = "GPL";

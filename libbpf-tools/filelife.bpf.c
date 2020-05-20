// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "filelife.h"

const volatile pid_t targ_tgid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct dentry *);
	__type(value, u64);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline int
probe_create(struct inode *dir, struct dentry *dentry)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	u64 ts;

	if (targ_tgid && targ_tgid != tgid)
		return 0;

	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start, &dentry, &ts, 0);
	return 0;
}

SEC("kprobe/vfs_create")
int BPF_KPROBE(kprobe__vfs_create, struct inode *dir, struct dentry *dentry)
{
	return probe_create(dir, dentry);
}

SEC("kprobe/security_inode_create")
int BPF_KPROBE(kprobe__security_inode_create, struct inode *dir,
	     struct dentry *dentry)
{
	return probe_create(dir, dentry);
}

SEC("kprobe/vfs_unlink")
int BPF_KPROBE(kprobe__vfs_unlink, struct inode *dir, struct dentry *dentry)
{
	u64 id = bpf_get_current_pid_tgid();
	struct event event = {};
	const u8 *qs_name_ptr;
	u32 tgid = id >> 32;
	u64 *tsp, delta_ns;
	u32 qs_len;

	tsp = bpf_map_lookup_elem(&start, &dentry);
	if (!tsp)
		return 0;   // missed entry

	delta_ns = bpf_ktime_get_ns() - *tsp;
	bpf_map_delete_elem(&start, &dentry);

	qs_name_ptr = BPF_CORE_READ(dentry, d_name.name);
	qs_len = BPF_CORE_READ(dentry, d_name.len);
	bpf_probe_read_kernel_str(&event.file, sizeof(event.file), qs_name_ptr);
	bpf_get_current_comm(&event.task, sizeof(event.task));
	event.delta_ns = delta_ns;
	event.tgid = tgid;

	/* output */
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

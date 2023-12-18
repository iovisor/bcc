// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "filelife.h"
#include "core_fixes.bpf.h"

/* linux: include/linux/fs.h */
#define FMODE_CREATED	0x100000

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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u32); /* tid */
	__type(value, struct event);
} currevent SEC(".maps");

static __always_inline int
probe_create(struct dentry *dentry)
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

/**
 * In different kernel versions, function vfs_create() has two declarations,
 * and their parameter lists are as follows:
 *
 * int vfs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
 *            bool want_excl);
 * int vfs_create(struct user_namespace *mnt_userns, struct inode *dir,
 *            struct dentry *dentry, umode_t mode, bool want_excl);
 * int vfs_create(struct mnt_idmap *idmap, struct inode *dir,
 *            struct dentry *dentry, umode_t mode, bool want_excl);
 */
SEC("kprobe/vfs_create")
int BPF_KPROBE(vfs_create, void *arg0, void *arg1, void *arg2)
{
	if (renamedata_has_old_mnt_userns_field()
		|| renamedata_has_new_mnt_idmap_field())
		return probe_create(arg2);
	else
		return probe_create(arg1);
}

SEC("kprobe/vfs_open")
int BPF_KPROBE(vfs_open, struct path *path, struct file *file)
{
	struct dentry *dentry = BPF_CORE_READ(path, dentry);
	int fmode = BPF_CORE_READ(file, f_mode);

	if (!(fmode & FMODE_CREATED))
		return 0;

	return probe_create(dentry);
}

SEC("kprobe/security_inode_create")
int BPF_KPROBE(security_inode_create, struct inode *dir,
	     struct dentry *dentry)
{
	return probe_create(dentry);
}

/**
 * In different kernel versions, function vfs_unlink() has two declarations,
 * and their parameter lists are as follows:
 *
 * int vfs_unlink(struct inode *dir, struct dentry *dentry,
 *        struct inode **delegated_inode);
 * int vfs_unlink(struct user_namespace *mnt_userns, struct inode *dir,
 *        struct dentry *dentry, struct inode **delegated_inode);
 * int vfs_unlink(struct mnt_idmap *idmap, struct inode *dir,
 *        struct dentry *dentry, struct inode **delegated_inode);
 */
SEC("kprobe/vfs_unlink")
int BPF_KPROBE(vfs_unlink, void *arg0, void *arg1, void *arg2)
{
	u64 id = bpf_get_current_pid_tgid();
	struct event event = {};
	const u8 *qs_name_ptr;
	u32 tgid = id >> 32;
	u32 tid = (u32)id;
	u64 *tsp, delta_ns;
	bool has_arg = renamedata_has_old_mnt_userns_field()
				|| renamedata_has_new_mnt_idmap_field();

	tsp = has_arg
		? bpf_map_lookup_elem(&start, &arg2)
		: bpf_map_lookup_elem(&start, &arg1);
	if (!tsp)
		return 0;   // missed entry

	delta_ns = bpf_ktime_get_ns() - *tsp;

	qs_name_ptr = has_arg
		? BPF_CORE_READ((struct dentry *)arg2, d_name.name)
		: BPF_CORE_READ((struct dentry *)arg1, d_name.name);

	bpf_probe_read_kernel_str(&event.file, sizeof(event.file), qs_name_ptr);
	bpf_get_current_comm(&event.task, sizeof(event.task));
	event.delta_ns = delta_ns;
	event.tgid = tgid;
	event.dentry = has_arg ? arg2 : arg1;

	bpf_map_update_elem(&currevent, &tid, &event, BPF_ANY);
	return 0;
}

SEC("kretprobe/vfs_unlink")
int BPF_KRETPROBE(vfs_unlink_ret)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 tid = (u32)id;
	int ret = PT_REGS_RC(ctx);
	struct event *event;

	event = bpf_map_lookup_elem(&currevent, &tid);
	if (!event)
		return 0;
	bpf_map_delete_elem(&currevent, &tid);

	/* skip failed unlink */
	if (ret)
		return 0;

	bpf_map_delete_elem(&start, &event->dentry);

	/* output */
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      event, sizeof(*event));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

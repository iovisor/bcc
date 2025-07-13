// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "filelife.h"
#include "compat.bpf.h"
#include "core_fixes.bpf.h"
#include "path_helpers.bpf.h"

/* linux: include/linux/fs.h */
#define FMODE_CREATED	0x100000

const volatile pid_t targ_tgid = 0;
const volatile bool full_path = false;

struct create_arg {
	u64 ts;
	struct vfsmount *cwd_vfsmnt;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct dentry *);
	__type(value, struct create_arg);
} start SEC(".maps");

struct unlink_event {
	__u64 delta_ns;
	pid_t tgid;
	struct dentry *dentry;
	struct vfsmount *cwd_vfsmnt;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u32); /* tid */
	__type(value, struct unlink_event);
} currevent SEC(".maps");

static __always_inline int
probe_create(struct dentry *dentry)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	struct create_arg arg = {};
	struct task_struct *task;

	if (targ_tgid && targ_tgid != tgid)
		return 0;

	task = (struct task_struct *)bpf_get_current_task_btf();

	arg.ts = bpf_ktime_get_ns();
	arg.cwd_vfsmnt = BPF_CORE_READ(task, fs, pwd.mnt);

	bpf_map_update_elem(&start, &dentry, &arg, 0);
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
	struct unlink_event unlink_event = {};
	struct create_arg *arg;
	u32 tgid = id >> 32;
	u32 tid = (u32)id;
	u64 delta_ns;
	bool has_arg = renamedata_has_old_mnt_userns_field()
				|| renamedata_has_new_mnt_idmap_field();

	arg = has_arg
		? bpf_map_lookup_elem(&start, &arg2)
		: bpf_map_lookup_elem(&start, &arg1);
	if (!arg)
		return 0;   // missed entry

	delta_ns = bpf_ktime_get_ns() - arg->ts;

	unlink_event.delta_ns = delta_ns;
	unlink_event.tgid = tgid;
	unlink_event.dentry = has_arg ? arg2 : arg1;
	unlink_event.cwd_vfsmnt = arg->cwd_vfsmnt;

	bpf_map_update_elem(&currevent, &tid, &unlink_event, BPF_ANY);
	return 0;
}

SEC("kretprobe/vfs_unlink")
int BPF_KRETPROBE(vfs_unlink_ret)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 tid = (u32)id;
	int ret = PT_REGS_RC(ctx);
	struct unlink_event *unlink_event;
	struct event *eventp;
	struct dentry *dentry;
	const u8 *qs_name_ptr;

	unlink_event = bpf_map_lookup_elem(&currevent, &tid);
	if (!unlink_event)
		return 0;
	bpf_map_delete_elem(&currevent, &tid);

	/* skip failed unlink */
	if (ret)
		return 0;

	eventp = reserve_buf(sizeof(*eventp));
	if (!eventp)
		return 0;

	eventp->tgid = unlink_event->tgid;
	eventp->delta_ns = unlink_event->delta_ns;
	bpf_get_current_comm(&eventp->task, sizeof(eventp->task));

	dentry = unlink_event->dentry;
	qs_name_ptr = BPF_CORE_READ(dentry, d_name.name);
	bpf_probe_read_kernel_str(&eventp->fname.pathes, sizeof(eventp->fname.pathes),
			   qs_name_ptr);
	eventp->fname.depth = 0;

	/* get full-path */
	if (full_path && eventp->fname.pathes[0] != '/')
		bpf_dentry_full_path(eventp->fname.pathes, NAME_MAX,
				MAX_PATH_DEPTH,
				unlink_event->dentry,
				unlink_event->cwd_vfsmnt,
				&eventp->fname.failed, &eventp->fname.depth);

	bpf_map_delete_elem(&start, &unlink_event->dentry);

	/* output */
	submit_buf(ctx, eventp, sizeof(*eventp));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

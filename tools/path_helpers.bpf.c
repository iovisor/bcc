// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Rong Tao */
#ifndef __PATH_HELPERS_BPF_H
#define __PATH_HELPERS_BPF_H 1

#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/mount.h>

/* see https://github.com/torvalds/linux/blob/master/fs/mount.h */
struct mount {
	struct hlist_node mnt_hash;
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
	/* ... */
};


static __always_inline
int bpf_dentry_full_path(char *pathes, int name_len, int max_depth,
			 struct dentry *dentry, struct vfsmount *vfsmnt,
			 __u32 *path_depth)
{
	struct dentry *parent_dentry, *mnt_root;
	struct mount *mnt;
	size_t filepart_length;
	char *payload = pathes;
	struct qstr d_name;
	int i;

	mnt = container_of(vfsmnt, struct mount, mnt);

	for (i = 1, payload += name_len; i < max_depth; i++) {
		bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name);
		filepart_length =
			bpf_probe_read_kernel_str(payload, name_len, (void *)d_name.name);

		if (filepart_length < 0 || filepart_length > name_len)
			break;

		bpf_probe_read_kernel(&mnt_root, sizeof(mnt_root), &vfsmnt->mnt_root);
		bpf_probe_read_kernel(&parent_dentry, sizeof(parent_dentry), &dentry->d_parent);

		if (dentry == parent_dentry || dentry == mnt_root) {
			struct mount *mnt_parent;
			bpf_probe_read_kernel(&mnt_parent, sizeof(mnt_parent), &mnt->mnt_parent);

			if (mnt != mnt_parent) {
				bpf_probe_read_kernel(&dentry, sizeof(dentry), &mnt->mnt_mountpoint);

				mnt = mnt_parent;
				vfsmnt = &mnt->mnt;

				bpf_probe_read_kernel(&mnt_root, sizeof(mnt_root), &vfsmnt->mnt_root);

				(*path_depth)++;
				payload += name_len;
				continue;
			} else {
				/* Real root directory */
				break;
			}
		}

		payload += name_len;

		dentry = parent_dentry;
		(*path_depth)++;
	}

	return 0;
}

static __always_inline
int bpf_getcwd(char *pathes, int name_len, int max_depth, __u32 *path_depth)
{
	struct task_struct *task;
        struct fs_struct *fs;
	struct dentry *dentry;
	struct vfsmount *vfsmnt;

	task = (struct task_struct *)bpf_get_current_task_btf();
	bpf_probe_read_kernel(&fs, sizeof(fs), &task->fs);
	bpf_probe_read_kernel(&dentry, sizeof(dentry), &fs->pwd.dentry);
	bpf_probe_read_kernel(&vfsmnt, sizeof(vfsmnt), &fs->pwd.mnt);

	return bpf_dentry_full_path(pathes, name_len, max_depth, dentry, vfsmnt,
			     path_depth);
}
#endif

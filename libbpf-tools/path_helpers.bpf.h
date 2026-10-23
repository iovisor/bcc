// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Rong Tao */
#ifndef __PATH_HELPERS_BPF_H
#define __PATH_HELPERS_BPF_H 1

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "path_helpers.h"


static __always_inline
int bpf_dentry_full_path(char *pathes, int name_len, int max_depth,
			 struct dentry *dentry, struct vfsmount *vfsmnt,
			 struct dentry *root_dentry, struct vfsmount *root_vfsmnt,
			 int *failed, __u32 *path_depth)
{
	int depth;
	struct dentry *parent_dentry, *mnt_root;
	struct mount *mnt;
	size_t filepart_length;
	char *payload = pathes;

	mnt = container_of(vfsmnt, struct mount, mnt);
	mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);

	for (depth = 0; depth < max_depth; depth++) {
		/* Do not walk out of this task's chroot or mount namespace root. */
		if (dentry == root_dentry && vfsmnt == root_vfsmnt)
			break;

		filepart_length =
			bpf_probe_read_kernel_str(payload, name_len,
					BPF_CORE_READ(dentry, d_name.name));

		if (filepart_length < 0) {
			*failed = 1;
			break;
		}

		if (filepart_length > name_len)
			break;

		parent_dentry = BPF_CORE_READ(dentry, d_parent);

		if (dentry == parent_dentry || dentry == mnt_root) {
			struct mount *mnt_parent;
			mnt_parent = BPF_CORE_READ(mnt, mnt_parent);

			if (mnt != mnt_parent) {
				dentry = BPF_CORE_READ(mnt, mnt_mountpoint);

				mnt = mnt_parent;
				vfsmnt = &mnt->mnt;

				mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);

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
int bpf_getcwd(char *pathes, int name_len, int max_depth, int *failed,
	       __u32 *path_depth)
{
	struct task_struct *task;
	struct dentry *dentry;
	struct vfsmount *vfsmnt;
	struct dentry *root_dentry;
	struct vfsmount *root_vfsmnt;

	task = (struct task_struct *)bpf_get_current_task_btf();
	dentry = BPF_CORE_READ(task, fs, pwd.dentry);
	vfsmnt = BPF_CORE_READ(task, fs, pwd.mnt);
	root_dentry = BPF_CORE_READ(task, fs, root.dentry);
	root_vfsmnt = BPF_CORE_READ(task, fs, root.mnt);

	return bpf_dentry_full_path(pathes, name_len, max_depth, dentry, vfsmnt,
			     root_dentry, root_vfsmnt, failed, path_depth);
}
#endif

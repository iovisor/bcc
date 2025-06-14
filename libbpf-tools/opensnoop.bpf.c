// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
// Copyright (c) 2020 Netflix
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "compat.bpf.h"
#include "opensnoop.h"

#ifndef O_CREAT
#define O_CREAT		00000100
#endif
#ifndef O_TMPFILE
#define O_TMPFILE	020200000
#endif

const volatile pid_t targ_pid = 0;
const volatile pid_t targ_tgid = 0;
const volatile uid_t targ_uid = 0;
const volatile bool targ_failed = false;
const volatile bool full_path = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct args_t);
} start SEC(".maps");

static __always_inline bool valid_uid(uid_t uid) {
	return uid != INVALID_UID;
}

static __always_inline
bool trace_allowed(u32 tgid, u32 pid)
{
	u32 uid;

	/* filters */
	if (targ_tgid && targ_tgid != tgid)
		return false;
	if (targ_pid && targ_pid != pid)
		return false;
	if (valid_uid(targ_uid)) {
		uid = (u32)bpf_get_current_uid_gid();
		if (targ_uid != uid) {
			return false;
		}
	}
	return true;
}

SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct syscall_trace_enter* ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	/* use kernel terminology here for tgid/pid: */
	u32 tgid = id >> 32;
	u32 pid = id;

	/* store arg info for later lookup */
	if (trace_allowed(tgid, pid)) {
		struct args_t args = {};
		args.fname = (const char *)ctx->args[0];
		args.flags = (int)ctx->args[1];
		args.mode = (__u32)ctx->args[2];
		bpf_map_update_elem(&start, &pid, &args, 0);
	}
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct syscall_trace_enter* ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	/* use kernel terminology here for tgid/pid: */
	u32 tgid = id >> 32;
	u32 pid = id;

	/* store arg info for later lookup */
	if (trace_allowed(tgid, pid)) {
		struct args_t args = {};
		args.fname = (const char *)ctx->args[1];
		args.flags = (int)ctx->args[2];
		args.mode = (__u32)ctx->args[3];
		bpf_map_update_elem(&start, &pid, &args, 0);
	}
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int tracepoint__syscalls__sys_enter_openat2(struct syscall_trace_enter* ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	/* use kernel terminology here for tgid/pid: */
	u32 tgid = id >> 32;
	u32 pid = id;

	/* store arg info for later lookup */
	if (trace_allowed(tgid, pid)) {
		struct args_t args = {};
		struct open_how how = {};
		args.fname = (const char *)ctx->args[1];
		bpf_probe_read_user(&how, sizeof(how), (void *)ctx->args[2]);
		args.flags = (int)how.flags;
		args.mode = (__u32)how.mode;
		bpf_map_update_elem(&start, &pid, &args, 0);
	}
	return 0;
}


static __always_inline
int trace_exit(struct syscall_trace_exit* ctx)
{
	struct event *eventp;
	struct args_t *ap;
	uintptr_t stack[3];
	int ret;
	u32 pid = bpf_get_current_pid_tgid();

	ap = bpf_map_lookup_elem(&start, &pid);
	if (!ap)
		return 0;	/* missed entry */
	ret = ctx->ret;
	if (targ_failed && ret >= 0)
		goto cleanup;	/* want failed only */

	eventp = reserve_buf(sizeof(*eventp));
	if (!eventp)
		goto cleanup;

	/* event data */
	eventp->pid = bpf_get_current_pid_tgid() >> 32;
	eventp->uid = bpf_get_current_uid_gid();
	bpf_get_current_comm(&eventp->comm, sizeof(eventp->comm));
	bpf_probe_read_user_str(&eventp->fname, sizeof(eventp->fname),
			  ap->fname);
	eventp->path_depth = 0;
	eventp->flags = ap->flags;

	if (ap->flags & O_CREAT || (ap->flags & O_TMPFILE) == O_TMPFILE)
		eventp->mode = ap->mode;
	else
		eventp->mode = 0;

	eventp->ret = ret;

	bpf_get_stack(ctx, &stack, sizeof(stack),
		      BPF_F_USER_STACK);
	/* Skip the first address that is usually the syscall it-self */
	eventp->callers[0] = stack[1];
	eventp->callers[1] = stack[2];

	if (full_path && eventp->fname[0] != '/') {
		int depth;
		struct task_struct *task;
		struct dentry *dentry, *parent_dentry, *mnt_root;
		struct vfsmount *vfsmnt;
		struct mount *mnt;
		size_t filepart_length;
		char *payload = eventp->fname;


		task = (struct task_struct *)bpf_get_current_task_btf();
		dentry = BPF_CORE_READ(task, fs, pwd.dentry);
		vfsmnt = BPF_CORE_READ(task, fs, pwd.mnt);
		mnt = container_of(vfsmnt, struct mount, mnt);
		mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);

		for (depth = 1, payload += NAME_MAX; depth < MAX_PATH_DEPTH; depth++) {
			filepart_length =
				bpf_probe_read_kernel_str(payload, NAME_MAX,
						BPF_CORE_READ(dentry, d_name.name));

			if (filepart_length < 0) {
				eventp->get_path_failed = 1;
				break;
			}

			if (filepart_length > NAME_MAX)
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

					eventp->path_depth++;
					payload += NAME_MAX;
					continue;
				} else {
					/* Real root directory */
					break;
				}
			}

			payload += NAME_MAX;

			dentry = parent_dentry;
			eventp->path_depth++;
		}
	}

	/* emit event */
	submit_buf(ctx, eventp, sizeof(*eventp));

cleanup:
	bpf_map_delete_elem(&start, &pid);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int tracepoint__syscalls__sys_exit_open(struct syscall_trace_exit* ctx)
{
	return trace_exit(ctx);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct syscall_trace_exit* ctx)
{
	return trace_exit(ctx);
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int tracepoint__syscalls__sys_exit_openat2(struct syscall_trace_exit* ctx)
{
	return trace_exit(ctx);
}

char LICENSE[] SEC("license") = "GPL";
